import argparse
import asyncio
import logging
import os
import pickle
import ssl
import time
import base64
from collections import deque
from typing import BinaryIO, Callable, Deque, Optional, Union, cast
from urllib.parse import urlparse
import csv # 1. Added import for CSV

import aioquic
import wsproto
import wsproto.events
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite, SessionTicket
from dnslib.dns import QTYPE, DNSHeader, DNSQuestion, DNSRecord

try:
    import uvloop
except ImportError:
    uvloop = None

logger = logging.getLogger("client")

HttpConnection = Union[H0Connection, H3Connection]

USER_AGENT = "aioquic/" + aioquic.__version__


class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = wsproto.Connection(wsproto.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """
        Perform the closing handshake.
        """
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=True)
        self.transmit()

    async def recv(self) -> str:
        """
        Receive the next message.
        """
        return await self.queue.get()

    async def send(self, message: str) -> None:
        """
        Send a message.
        """
        assert isinstance(message, str)

        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=False)
        self.transmit()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)

        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, csv_writer=None, **kwargs) -> None: # 2. Added csv_writer to init
        super().__init__(*args, **kwargs)

        self.key_update = False
        self.pushes: dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: dict[int, Deque[H3Event]] = {}
        self._request_waiter: dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: dict[int, WebSocket] = {}
        self.csv_writer = csv_writer # 2. Store csv_writer

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    async def get(self, url: str, headers: Optional[dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )

    async def dns_query(self, url: str, query_name: str, query_type: str) -> DNSRecord:
        """
        Perform a DNS query using DNS over HTTPS (DoH).
        """
        t1 = time.time() # 4. Start timing

        # Create DNS query
        query = DNSRecord(
            header=DNSHeader(id=0),
            q=DNSQuestion(query_name, getattr(QTYPE, query_type)),
        )
        dns_wire = bytes(query.pack())
        
        # Encode as base64url for GET request (RFC 8484)
        dns_query_base64 = base64.urlsafe_b64encode(dns_wire).decode('utf-8').rstrip('=')
        
        # Construct DoH URL with dns parameter
        doh_url = f"{url}?dns={dns_query_base64}"
        
        t2 = time.time() # 4. Time after query preparation
        
        logger.info(f"Sending DNS query for {query_name} (type: {query_type})")
        
        # Send GET request with appropriate headers
        http_events = await self.get(
            doh_url,
            headers={
                "accept": "application/dns-message"
            }
        )
        
        t3 = time.time() # 4. Time after awaiting HTTP response

        # Extract DNS response from HTTP response
        dns_response = b""
        for event in http_events:
            if isinstance(event, DataReceived):
                dns_response += event.data
        
        # Parse DNS response
        answer = DNSRecord.parse(dns_response)
        
        t4 = time.time() # 4. Time after parsing response

        # 4. Timing breakdown and logging
        query_creation_time = t2 - t1
        wait_for_response_time = t3 - t2 # Includes network latency and server processing
        response_parsing_time = t4 - t3
        total_time = t4 - t1

        print("\n--- Client DoH Timing Breakdown ---")
        print("{:<30} {:<10}".format("Operation", "Time (s)"))
        print("{:<30} {:<10.6f}".format("Query Creation & Encoding", query_creation_time))
        print("{:<30} {:<10.6f}".format("Wait for HTTP Response", wait_for_response_time))
        print("{:<30} {:<10.6f}".format("Response Processing & Parsing", response_parsing_time))
        print("-------------------------------")
        print("{:<30} {:<10.6f}".format("Total Query Time", total_time))
        print("-------------------------------")

        if self.csv_writer:
            self.csv_writer.writerow([
                query_name,
                f"{query_creation_time:.6f}",
                f"{wait_for_response_time:.6f}",
                f"{response_parsing_time:.6f}",
                f"{total_time:.6f}"
            ])
            
        return answer

    async def websocket(
        self, url: str, subprotocols: Optional[list[str]] = None
    ) -> WebSocket:
        """
        Open a WebSocket.
        """
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        websocket = WebSocket(
            http=self._http, stream_id=stream_id, transmit=self.transmit
        )

        self._websockets[stream_id] = websocket

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode())
            )
        self._http.send_headers(stream_id=stream_id, headers=headers)

        self.transmit()

        return websocket

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

            # Request a key update for interoperability testing.
            if self.key_update:
                logger.info("Requesting key update")
                self.request_key_update()
                self.key_update = False

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
                (b"user-agent", USER_AGENT.encode()),
            ]
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def main(
    configuration: QuicConfiguration,
    server_host: str,
    server_port: int,
    local_port: int,
    query_name: str,
    query_type: str,
    doh_path: str,
    timing_log_file: Optional[str] = None # 3. Added timing_log_file argument
) -> None:
    # 3. CSV file setup
    csv_file = None
    csv_writer = None
    if timing_log_file:
        file_exists = os.path.exists(timing_log_file)
        file_is_empty = not file_exists or os.path.getsize(timing_log_file) == 0
        try:
            csv_file = open(timing_log_file, 'a', newline='')
            csv_writer = csv.writer(csv_file)
            if file_is_empty:
                csv_writer.writerow(['Domain queried','Query_Creation_Encoding_s','Wait_for_HTTP_Response_s','Response_Processing_Parsing_s','Total_Time_s'])
            logger.info(f"Timing data will be logged to {timing_log_file}")
        except Exception as e:
            logger.error(f"Could not open CSV file {timing_log_file}: {e}")
            csv_writer = None

    logger.info(f"Connecting to DoH server at {server_host}:{server_port}")

    async with connect(
        server_host,
        server_port,
        configuration=configuration,
        # 3. Pass csv_writer to HttpClient
        create_protocol=lambda *a, **kw: HttpClient(*a, csv_writer=csv_writer, **kw),
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
    ) as client:
        client = cast(HttpClient, client)
        
        # Construct DoH URL
        doh_url = f"https://{server_host}:{server_port}{doh_path}"
        
        # Perform DNS query
        logger.info(f"Querying {query_name} (type: {query_type})")
        answer = await client.dns_query(doh_url, query_name, query_type)
        logger.info("Received DNS answer:\n%s" % answer)
        
        client.close(error_code=ErrorCode.H3_NO_ERROR)
        
    if csv_file: # 3. Close CSV file
        csv_file.close()


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="DNS over HTTPS (DoH) Client")
    parser.add_argument(
        "--server",
        type=str,
        required=True,
        help="DoH server address (hostname or IP)",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=4433,
        help="DoH server port (defaults to 4433)",
    )
    parser.add_argument(
        "--query-name",
        type=str,
        required=True,
        help="Domain name to query (e.g., example.com)",
    )
    parser.add_argument(
        "--query-type",
        type=str,
        default="A",
        help="DNS query type (default: A)",
    )
    parser.add_argument(
        "--doh-path",
        type=str,
        default="/dns-query",
        help="DoH endpoint path (default: /dns-query)",
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument( # 5. Added timing-log argument
        "--timing-log",
        type=str,
        default=None,
        help="Path to a CSV file to log query timing."
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass

    if uvloop is not None:
        uvloop.install()
        
    asyncio.run(
        main(
            configuration=configuration,
            server_host=args.server,
            server_port=args.server_port,
            local_port=args.local_port,
            query_name=args.query_name,
            query_type=args.query_type,
            doh_path=args.doh_path,
            timing_log_file=args.timing_log # 3. Pass timing-log value
        )
    )
