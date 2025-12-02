import argparse
import asyncio
import logging
import pickle
import ssl
import struct
import time
from typing import Dict, Optional, cast
import os 
import csv

from aioquic.asyncio import QuicConnectionProtocol, serve, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import SessionTicket
from dnslib.dns import DNSRecord, QTYPE, DNSHeader, DNSQuestion

logger = logging.getLogger("doq_proxy")

#SessionTicketStore reused from doq_server.py
class SessionTicketStore:
    """
    Simple in-memory store for TLS session tickets.
    This helps resume QUIC connections faster by reusing session parameters.
    """
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        """Adds a session ticket to the store."""
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        """Retrieves and removes a session ticket from the store."""
        return self.tickets.pop(label, None)


#ProxyDnsClientProtocol modified from doq_client.py
class ProxyDnsClientProtocol(QuicConnectionProtocol):
    """
    A QUIC protocol implementation for the proxy's internal client role.
    It's responsible for sending DNS queries to the upstream DoQ server
    and receiving their responses.
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[DNSRecord]] = None #a Future to hold the result of an ongoing DNS query

    async def query(self, dns_query_data: bytes) -> DNSRecord:
        """
        Sends a raw DNS query over a new QUIC stream to the upstream server
        and waits for the DNS answer.

        Args:
            dns_query_data: The raw bytes of the DNS query.

        Returns:
            A DNSRecord object representing the DNS response.
        """
        data_with_length = dns_query_data    
        print("Proxy(clientside) forwards query data:", data_with_length)
        stream_id = self._quic.get_next_available_stream_id() #obtain a new stream ID and send the data, indicating the end of the stream
        self._quic.send_stream_data(stream_id, data_with_length, end_stream=True)
        logger.debug(f"Proxy client: Sent query on stream {stream_id} to upstream.")
        waiter = self._loop.create_future() #create a Future to wait for the response on this stream
        self._ack_waiter = waiter
        self.transmit() #ensure the QUIC data is scheduled for transmission
        dns_response_record = await asyncio.shield(waiter) #wait for the response to be received and the waiter to be set
        return dns_response_record

    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Handles incoming QUIC events from the upstream DoQ server.
        Specifically, it processes StreamDataReceived events containing DNS responses.
        """
        if self._ack_waiter is not None and not self._ack_waiter.done():
            if isinstance(event, StreamDataReceived):
                logger.debug(f"Proxy client: Received stream data on stream {event.stream_id} from upstream.")
                try:
                    answer = event.data
                    print(f"Proxy(clientside) receives encrypted answer:{answer}" )
                    waiter = self._ack_waiter
                    self._ack_waiter = None
                    waiter.set_result(answer)
                except Exception as e:
                    logger.error(f"Proxy client: Error parsing upstream DNS response: {e}")
                    self._ack_waiter.set_exception(e)
                    self._ack_waiter = None
        #other QUIC events (e.g., ConnectionTerminated) are handled by the base class
#ProxyDnsServerProtocol modified from doq_server.py
class ProxyDnsServerProtocol(QuicConnectionProtocol):
    """
    A QUIC protocol implementation for the proxy's server role.
    It listens for incoming DNS over QUIC requests from downstream clients,
    forwards them to an upstream DoQ server, and sends the response back.
    """
    def __init__(
        self,
        *args,
        upstream_host: str,
        upstream_port: int,
        upstream_quic_configuration: QuicConfiguration,
        csv_writer=None, 
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_quic_configuration = upstream_quic_configuration
        logger.info(f"Proxy server: Initialized for upstream {upstream_host}:{upstream_port}")
        self.timing_data = {}
        self.csv_writer = csv_writer

    async def _forward_query(self, query_data: bytes) -> bytes:
        """
        Establishes a QUIC connection to the upstream DoQ server,
        sends the provided DNS query data, and returns the raw DNS response bytes.

        Args:
            query_data: The raw bytes of the DNS query (without length prefix).

        Returns:
            The raw bytes of the DNS response from the upstream server, or an empty bytes
            object if an error occurred.
        """
        logger.debug(f"Proxy server: Forwarding query to upstream {self.upstream_host}:{self.upstream_port}")

        upstream_client_proto = None #initialize

        try:
            #establish a client-side QUIC connection to the upstream server
            async with connect(
                self.upstream_host,
                self.upstream_port,
                configuration=self.upstream_quic_configuration,
                create_protocol=ProxyDnsClientProtocol,
            ) as client_proto:
                upstream_client_proto = cast(ProxyDnsClientProtocol, client_proto)
                print("Proxy(serverside) forwards query data:", query_data)
                dns_response_record = await upstream_client_proto.query(query_data) #send the raw DNS query to the upstream via our internal client protocol
                logger.debug("Proxy server: Received response from upstream.")
                return dns_response_record 
        except ConnectionError as exc:
            logger.error(f"Proxy server: Failed to connect to upstream server or send query: {exc}")      
            return b"" #return empty if forwarding fails
        except Exception as exc:
            logger.error(f"Proxy server: An unexpected error occurred during upstream forwarding: {exc}") 
            return b""

    def quic_event_received(self, event: QuicEvent):
        """
        Handles incoming QUIC events from downstream clients connected to the proxy.
        When a DNS query is received, it initiates the forwarding process.
        """
        if isinstance(event, StreamDataReceived) and event.end_stream:
            logger.debug(f"Proxy server: Received StreamDataReceived from client on stream {event.stream_id}.")
            try:
                t_receive_start = time.time() #start timing for client query reception
                print("At time: ", t_receive_start, ", Proxy receives from client an encrypted query: ", event.data) #forward the full data
                self.timing_data['proxy_received_client_query_at_time'] = t_receive_start
                asyncio.ensure_future(
                        self._handle_client_query(event.stream_id, event.data, t_receive_start)
                )
            except Exception as e:
                logger.error(f"Proxy server: Error parsing client query on stream {event.stream_id}: {e}")
                self._quic.send_stream_data(event.stream_id, b"", end_stream=True) #send an empty or error response back to the client if parsing fails
                self.transmit()
    
    async def _dynamic_forward_query(self, host, port, payload):
        try:
            async with connect(
                host,
                port,
                configuration=self.upstream_quic_configuration,
                create_protocol=ProxyDnsClientProtocol,
            ) as client_proto:
    
                client_proto = cast(ProxyDnsClientProtocol, client_proto)
                dns_response = await client_proto.query(payload)
                return dns_response

        except Exception as e:
            logger.error(f"Proxy: error contacting upstream {host}:{port}: {e}")
            return b""


    async def _handle_client_query(self, client_stream_id: int, raw_client_data: bytes, t_receive_start: float):
        """
        Forwards the entire encrypted query from the client to the upstream server,
        and relays the upstream encrypted response back to the client.
        """
        # Parse header: host_len, host, port
        t_processing_start=time.time()
        offset = 0
        host_len = raw_client_data[offset]
        offset += 1

        up_host = raw_client_data[offset:offset + host_len].decode()
        offset += host_len

        up_port = struct.unpack("!H", raw_client_data[offset:offset+2])[0]
        offset += 2

        forward_payload = raw_client_data[offset:]
	t_processing_end=time.time()
        upstream_response = await self._dynamic_forward_query(up_host, up_port, forward_payload) #forward the client payload to upstream
        t_recv = time.time()
	self.timing_data['proxy_extracted_metadata_s'] = t_processing_end-t_processing_start
        print("Proxy(serverside) receives encrypted answer:", upstream_response)
        t1=time.time()
        if upstream_response:
                t_sent=time.time()
                self._quic.send_stream_data(client_stream_id, upstream_response, end_stream=True) #send the upstream response directly back to the client with no length prefix
                logger.debug(f"Proxy server: Sent upstream response back to client on stream {client_stream_id}.")
        else:
                logger.warning(f"Proxy server: No response from upstream for stream {client_stream_id}, sending empty response to client.")
                self._quic.send_stream_data(client_stream_id, b"", end_stream=True)

        self.transmit()
        t_transmit_end = time.time()
        self.timing_data['client_response_transmit'] = t_transmit_end - t1
        total_time = t_transmit_end - t_receive_start
        print("\n--- Proxy Server (Downstream) Timing Breakdown ---")
        print("{:<35} {:<10}".format("Operation", "Time (s)"))
        print("{:<35} {:<10.6f}".format("Query received at", t_receive_start))
        print("{:<35} {:<10.6f}".format("Extracted metadata in", self.timing_data.get('proxy_extracted_metadata_s', 0.0)))
        print("{:<35} {:<10.6f}".format("Forwarded at", t_processing_end)) # Detailed client timing
        print("{:<35} {:<10.6f}".format("Received response from resolver at", t_recv)) # Detailed client timing
        print("{:<35} {:<10.6f}".format("Sent to client at", t_sent))
        print("{:<35} {:<10.6f}".format("TOTAL Proxy Handling Time (s)", total_time))
        print("-------------------------------------------------")
        if self.csv_writer:
            try:
                self.csv_writer.writerow([
                    f"{t_receive_start:.6f}",
                    f"{self.timing_data.get('proxy_extracted_metadata_s', 0.0):.6f}",
                    f"{t_processing_end:.6f}",
                    f"{t_recv:.6f}",
                    f"{t_sent:.6f}",
                    f"{total_time:.6f}"
                ])
            except Exception as e:
                logger.error(f"Error writing to proxy timing CSV: {e}")
                
     
#Main
async def main(
    listen_host: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    proxy_server_configuration: QuicConfiguration,
    proxy_client_configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
    csv_writer,
) -> None:
    """
    Sets up and runs the DNS over QUIC proxy server.
    """
    logger.info(f"Starting DNS over QUIC proxy on {listen_host}:{listen_port}")
    logger.info(f"Configured to forward to upstream DoQ server at {upstream_host}:{upstream_port}")       

    #serve function starts a QUIC server. The lambda creates ProxyDnsServerProtocol instances for passing the upstream configuration.
    await serve(
        listen_host,
        listen_port,
        configuration=proxy_server_configuration,
        create_protocol=lambda *args, **kwargs: ProxyDnsServerProtocol(
            *args,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            upstream_quic_configuration=proxy_client_configuration,
            csv_writer=csv_writer,
            **kwargs
        ),
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    await asyncio.Future() #proxy server listens indefinitely until a KeyboardInterrupt or other error.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC proxy")
    parser.add_argument(
        "--listen-host",
        type=str,
        default="::", #listens on all available IPv6 and IPv4 interfaces by default
        help="The address the proxy server will listen on (defaults to '::')",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8053,
        help="The port the proxy server will listen on (defaults to 8053)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        required=True, 
        help="Path to the TLS private key file for the proxy server",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True, 
        help="Path to the TLS certificate file for the proxy server",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="Enable sending QUIC Retry packets for new connections to the proxy",
    )
    parser.add_argument(
        "--upstream-host",
        type=str,
        required=False, #the hostname or IP of the actual upstream DoQ server is mandatory
        help="The remote upstream DoQ server's host name or IP address",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=853, #standard DoQ port
        required=False,
        help="The remote upstream DoQ server's port number (defaults to 853)",
    )
    parser.add_argument(
        "--ca-certs",
        type=str,
        help="Path to CA certificates file to trust the upstream server's certificate. "
             "For self-signed upstream, this should be the upstream's 'server.pem'.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not validate the upstream server's certificate (use with extreme caution!)",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="Directory to log QUIC events to QLOG files for debugging",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increase logging verbosity to DEBUG level"
    )
    parser.add_argument(
        "--timing-log",
        type=str,
        default=None,
        help="Path to a CSV file to log proxy timing analysis.", 
    )

    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    quic_logger = QuicFileLogger(args.quic_log) if args.quic_log else None
    proxy_server_configuration = QuicConfiguration(
        alpn_protocols=["doq"], #application-Layer Protocol Negotiation for DNS over QUIC
        is_client=False, #this configuration is for server role
        quic_logger=quic_logger,
    )
    proxy_server_configuration.load_cert_chain(args.certificate, args.private_key)
    proxy_client_configuration = QuicConfiguration(
        alpn_protocols=["doq"],
        is_client=True, #configuration for client role
        quic_logger=quic_logger,
    )
    if args.ca_certs:
        proxy_client_configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        proxy_client_configuration.verify_mode = ssl.CERT_NONE

    session_ticket_store = SessionTicketStore() #create an in-memory session ticket store for the proxy server to optimize reconnections
    csv_file = None
    csv_writer = None
    
    if args.timing_log:
        file_exists = os.path.exists(args.timing_log)
        file_is_empty = not file_exists or os.path.getsize(args.timing_log) == 0
        try:
            csv_file = open(args.timing_log, 'a', newline='')
            csv_writer = csv.writer(csv_file)
            if file_is_empty:
                csv_writer.writerow([
                    'Query_Receive_at',
                    'Extracted_Metadata_s',
                    'Forwards_at',
                    'Receives_Response_at',
                    'Response_Sent_at',
                    'TOTAL_Time_s'
                ])
            logging.info(f"Timing data will be logged to {args.timing_log}")
        except Exception as e:
            logging.error(f"Could not open CSV file {args.timing_log}: {e}")
            csv_writer = None
    try:
        asyncio.run(
            main(
                listen_host=args.listen_host,
                listen_port=args.listen_port,
                upstream_host=args.upstream_host,
                upstream_port=args.upstream_port,
                proxy_server_configuration=proxy_server_configuration,
                proxy_client_configuration=proxy_client_configuration,
                session_ticket_store=session_ticket_store,
                retry=args.retry,
                csv_writer=csv_writer,
            )
        )
    except KeyboardInterrupt:
        logger.info("DNS over QUIC proxy stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"DNS over QUIC proxy encountered a fatal error: {e}", exc_info=True)
    finally:
        if csv_file:
            csv_file.close()
