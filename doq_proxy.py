import argparse
import asyncio
import logging
import pickle
import ssl
import struct
import time
from typing import Dict, Optional, cast
import os # NEW
import csv # NEW

from aioquic.asyncio import QuicConnectionProtocol, serve, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import SessionTicket
from dnslib.dns import DNSRecord, QTYPE, DNSHeader, DNSQuestion

logger = logging.getLogger("doq_proxy")

# --- SessionTicketStore (Reused from doq_server.py) ---
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


# --- ProxyDnsClientProtocol (Modified from doq_client.py) ---
class ProxyDnsClientProtocol(QuicConnectionProtocol):
    """
    A QUIC protocol implementation for the proxy's internal client role.
    It's responsible for sending DNS queries to the upstream DoQ server
    and receiving their responses.
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # A Future to hold the result of an ongoing DNS query
        self._ack_waiter: Optional[asyncio.Future[DNSRecord]] = None
        # Store for client-side timing
        self.client_timing_data = {} # NEW

    async def query(self, dns_query_data: bytes) -> DNSRecord:
        """
        Sends a raw DNS query over a new QUIC stream to the upstream server
        and waits for the DNS answer.

        Args:
            dns_query_data: The raw bytes of the DNS query.

        Returns:
            A DNSRecord object representing the DNS response.
        """
        # DNS over QUIC requires a 2-byte length prefix for the DNS message
        t1=time.time()
        data_with_length = dns_query_data #struct.pack("!H", len(dns_query_data)) + dns_query_data        
        t3=time.time() # This t3 is actually t_setup_end
        print("Proxy(clientside) forwards query data:", data_with_length)
        t4=time.time() # This t4 is actually t_setup_start for transmission

        # Obtain a new stream ID and send the data, indicating the end of the stream
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data_with_length, end_stream=True)
        logger.debug(f"Proxy client: Sent query on stream {stream_id} to upstream.")
        t2=time.time() # This t2 is actually t_transmission_start_wait

        # Create a Future to wait for the response on this stream
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit() # Ensure the QUIC data is scheduled for transmission

        # Wait for the response to be received and the waiter to be set
        dns_response_record = await asyncio.shield(waiter)
        t5=time.time() # End timing for wait and receive (was t3)

        # Calculate and store client timing (Proxy to Upstream)
        t_setup = (t3-t1) + (t2-t4) # Approximate
        t_wait = t5-t2

        self.client_timing_data['client_query_setup'] = t_setup
        self.client_timing_data['client_wait_response'] = t_wait

        # --- NEW PROXY CLIENT TIMING OUTPUT ---
        print("\n--- Proxy Client (Upstream) Timing Breakdown ---")
        print("{:<30} {:<10}".format("Operation", "Time (s)"))
        print("{:<30} {:<10.6f}".format("Query transmission setup", self.client_timing_data['client_query_setup']))
        print("{:<30} {:<10.6f}".format("Wait for encrypted response", self.client_timing_data['client_wait_response']))
        print("-----------------------------------------------")
        # --- END NEW PROXY CLIENT TIMING OUTPUT ---

        return dns_response_record

    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Handles incoming QUIC events from the upstream DoQ server.
        Specifically, it processes StreamDataReceived events containing DNS responses.
        """
        if self._ack_waiter is not None and not self._ack_waiter.done():
            if isinstance(event, StreamDataReceived):
                logger.debug(f"Proxy client: Received stream data on stream {event.stream_id} from upstream.")
                # Parse DNS answer, which includes the 2-byte length prefix
                # The event.data contains the length prefix + DNS message
                try:
                    #length = struct.unpack("!H", bytes(event.data[:2]))[0]
                    answer = event.data#DNSRecord.parse(event.data[2 : 2 + length])
                    print("Proxy(clientside) receives encrypted answer:", answer)
                    # Set the result of the pending query
                    waiter = self._ack_waiter
                    self._ack_waiter = None
                    waiter.set_result(answer)
                except Exception as e:
                    logger.error(f"Proxy client: Error parsing upstream DNS response: {e}")
                    # Optionally, set an error result on the waiter
                    self._ack_waiter.set_exception(e)
                    self._ack_waiter = None
        # Other QUIC events (e.g., ConnectionTerminated) are handled by the base class


# --- ProxyDnsServerProtocol (Modified from doq_server.py) ---
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
        csv_writer=None, # NEW
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_quic_configuration = upstream_quic_configuration
        logger.info(f"Proxy server: Initialized for upstream {upstream_host}:{upstream_port}")
        # Store for timing measurements
        self.timing_data = {}
        self.csv_writer = csv_writer # NEW

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
        t_forward_start = time.time()
        logger.debug(f"Proxy server: Forwarding query to upstream {self.upstream_host}:{self.upstream_port}")

        upstream_client_proto = None # Initialize
        upstream_client_proto_timing = {} # To capture client-side timing

        try:
            # Establish a client-side QUIC connection to the upstream server
            # NOTE: Connection establishment time is included in the total forward time.
            async with connect(
                self.upstream_host,
                self.upstream_port,
                configuration=self.upstream_quic_configuration,
                create_protocol=ProxyDnsClientProtocol,
                # Session ticket handling for the proxy's internal client could be added here
            ) as client_proto:
                t_connect_end = time.time()
                self.timing_data['upstream_connect'] = t_connect_end - t_forward_start

                upstream_client_proto = cast(ProxyDnsClientProtocol, client_proto)
                print("Proxy(serverside) forwards query data:", query_data)

                # Send the raw DNS query to the upstream via our internal client protocol
                dns_response_record = await upstream_client_proto.query(query_data)

                # Capture the client-side timing breakdown from the protocol instance
                upstream_client_proto_timing = upstream_client_proto.client_timing_data

                t_forward_end = time.time()
                # Recalculate upstream_query_wait from proxy's perspective. It should cover
                # query setup + wait for response from the ProxyDnsClientProtocol perspective.
                # Since the client timing is now detailed, we use the total time spent in client.query()  
                # for the 'upstream_query_wait' in the server-side breakdown.
                self.timing_data['upstream_query_wait'] = t_forward_end - t_connect_end

                logger.debug("Proxy server: Received response from upstream.")

                # Pack the DNSRecord object back into raw bytes for sending back
                return dns_response_record
        except ConnectionError as exc:
            t_forward_end = time.time()
            self.timing_data['upstream_query_wait'] = t_forward_end - t_connect_end # Use connect_end if connection succeeded, else t_forward_start
            logger.error(f"Proxy server: Failed to connect to upstream server or send query: {exc}")      
            return b"" # Return empty if forwarding fails
        except Exception as exc:
            t_forward_end = time.time()
            self.timing_data['upstream_query_wait'] = t_forward_end - t_connect_end
            logger.error(f"Proxy server: An unexpected error occurred during upstream forwarding: {exc}") 
            return b""
        finally:
            # Store the detailed client-side timing data for logging in _handle_client_query
            self.timing_data['upstream_client_timing'] = upstream_client_proto_timing

    def quic_event_received(self, event: QuicEvent):
        """
        Handles incoming QUIC events from downstream clients connected to the proxy.
        When a DNS query is received, it initiates the forwarding process.
        """
        if isinstance(event, StreamDataReceived) and event.end_stream:
            logger.debug(f"Proxy server: Received StreamDataReceived from client on stream {event.stream_id}.")
            try:
                t_receive_start = time.time() # Start timing for client query reception
                print("Proxy(serverside) receives encrypted query1 :", event.data)
                # Just forward the full data
                asyncio.ensure_future(
                        self._handle_client_query(event.stream_id, event.data, t_receive_start)
                )
            except Exception as e:
                logger.error(f"Proxy server: Error parsing client query on stream {event.stream_id}: {e}")
                # Send an empty or error response back to the client if parsing fails
                self._quic.send_stream_data(event.stream_id, b"", end_stream=True)
                self.transmit()

    async def _handle_client_query(self, client_stream_id: int, raw_client_data: bytes, t_receive_start: float):
        """
        Forwards the entire encrypted query from the client to the upstream server,
        and relays the upstream encrypted response back to the client.
        """
        t_receive_end = time.time()
        self.timing_data['client_receive_and_prep'] = t_receive_end - t_receive_start

        # Forward the entire raw client payload to upstream
        upstream_response = await self._forward_query(raw_client_data)
        t_forward_end = time.time()

        print("Proxy(serverside) receives encrypted answer:", upstream_response)
        t1=time.time()
        if upstream_response:
                # Send the upstream response directly back to the client (no length prefix)
                self._quic.send_stream_data(client_stream_id, upstream_response, end_stream=True)
                logger.debug(f"Proxy server: Sent upstream response back to client on stream {client_stream_id}.")
        else:
                # If no response was received from upstream, send an empty response to the client
                logger.warning(f"Proxy server: No response from upstream for stream {client_stream_id}, sending empty response to client.")
                self._quic.send_stream_data(client_stream_id, b"", end_stream=True)

        self.transmit()
        t_transmit_end = time.time()
        self.timing_data['client_response_transmit'] = t_transmit_end - t1

        total_time = t_transmit_end - t_receive_start

        # --- NEW PROXY SERVER TIMING OUTPUT ---
        print("\n--- Proxy Server (Downstream) Timing Breakdown ---")
        print("{:<35} {:<10}".format("Operation", "Time (s)"))
        print("{:<35} {:<10.6f}".format("Client query receive & prep", self.timing_data.get('client_receive_and_prep', 0.0)))
        print("{:<35} {:<10.6f}".format("Upstream connection establishment", self.timing_data.get('upstream_connect', 0.0)))
        print("{:<35} {:<10.6f}".format("Upstream query transmission setup", self.timing_data.get('upstream_client_timing', {}).get('client_query_setup', 0.0))) # Detailed client timing
        print("{:<35} {:<10.6f}".format("Wait for upstream encrypted response", self.timing_data.get('upstream_client_timing', {}).get('client_wait_response', 0.0))) # Detailed client timing
        print("{:<35} {:<10.6f}".format("Client response transmit setup", self.timing_data.get('client_response_transmit', 0.0)))
        print("{:<35} {:<10.6f}".format("TOTAL Proxy Handling Time (s)", total_time))
        print("-------------------------------------------------")
        # --- END NEW PROXY SERVER TIMING OUTPUT ---

        # NEW: Write to CSV
        if self.csv_writer:
            # We can't easily extract the domain, so we log "ENCRYPTED_QUERY"
            try:
                self.csv_writer.writerow([
                    "ENCRYPTED_QUERY",
                    f"{self.timing_data.get('client_receive_and_prep', 0.0):.6f}",
                    f"{self.timing_data.get('upstream_connect', 0.0):.6f}",
                    f"{self.timing_data.get('upstream_client_timing', {}).get('client_query_setup', 0.0):.6f}",
                    f"{self.timing_data.get('upstream_client_timing', {}).get('client_wait_response', 0.0):.6f}",
                    f"{self.timing_data.get('client_response_transmit', 0.0):.6f}",
                    f"{total_time:.6f}"
                ])
                self._quic.parent_connection.csv_file.flush() # Ensure data is written immediately        
            except Exception as e:
                logger.error(f"Error writing to proxy timing CSV: {e}")
        # END NEW: Write to CSV

# --- Main function ---
async def main(
    listen_host: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    proxy_server_configuration: QuicConfiguration,
    proxy_client_configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
    csv_writer, # NEW
) -> None:
    """
    Sets up and runs the DNS over QUIC proxy server.
    """
    logger.info(f"Starting DNS over QUIC proxy on {listen_host}:{listen_port}")
    logger.info(f"Configured to forward to upstream DoQ server at {upstream_host}:{upstream_port}")       

    # The `serve` function starts a QUIC server. We provide a lambda to create
    # `ProxyDnsServerProtocol` instances, passing the upstream configuration.
    await serve(
        listen_host,
        listen_port,
        configuration=proxy_server_configuration,
        create_protocol=lambda *args, **kwargs: ProxyDnsServerProtocol(
            *args,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            upstream_quic_configuration=proxy_client_configuration,
            csv_writer=csv_writer, # NEW
            **kwargs
        ),
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    # The proxy server runs indefinitely until a KeyboardInterrupt or other error.
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC proxy")

    # --- Arguments for the proxy's server-facing side (for incoming client connections) ---
    parser.add_argument(
        "--listen-host",
        type=str,
        default="::", # Listens on all available IPv6 and IPv4 interfaces by default
        help="The address the proxy server will listen on (defaults to '::')",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8053, # Using a common alternative port for DNS over QUIC for proxy
        help="The port the proxy server will listen on (defaults to 8053)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        required=True, # The proxy needs its own TLS private key
        help="Path to the TLS private key file for the proxy server",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True, # The proxy needs its own TLS certificate
        help="Path to the TLS certificate file for the proxy server",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="Enable sending QUIC Retry packets for new connections to the proxy",
    )

    # --- Arguments for the proxy's client-facing side (for outgoing connections to upstream DoQ server) ---
    parser.add_argument(
        "--upstream-host",
        type=str,
        required=True, # The hostname or IP of the actual upstream DoQ server is mandatory
        help="The remote upstream DoQ server's host name or IP address",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=853, # Standard DoQ port for the upstream server
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

    # --- Common logging and QUIC logging arguments ---
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="Directory to log QUIC events to QLOG files for debugging",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increase logging verbosity to DEBUG level"
    )

    parser.add_argument( # NEW
        "--timing-log",
        type=str,
        default=None,
        help="Path to a CSV file to log proxy timing analysis.", # NEW
    )

    args = parser.parse_args()

    # Configure logging based on verbose flag
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # Initialize QUIC logger if path is provided
    quic_logger = QuicFileLogger(args.quic_log) if args.quic_log else None

    # --- Configure the proxy's server-side (for clients connecting to the proxy) ---
    proxy_server_configuration = QuicConfiguration(
        alpn_protocols=["doq"], # Application-Layer Protocol Negotiation for DNS over QUIC
        is_client=False, # This configuration is for a server role
        quic_logger=quic_logger,
    )
    # Load the proxy's own certificate and private key
    proxy_server_configuration.load_cert_chain(args.certificate, args.private_key)

    # --- Configure the proxy's client-side (for connecting to the upstream DoQ server) ---
    proxy_client_configuration = QuicConfiguration(
        alpn_protocols=["doq"],
        is_client=True, # This configuration is for a client role
        quic_logger=quic_logger,
    )
    # Load CA certificates to trust the upstream server's certificate
    if args.ca_certs:
        proxy_client_configuration.load_verify_locations(args.ca_certs)
    # Optionally disable certificate validation for upstream (not recommended for production)
    if args.insecure:
        proxy_client_configuration.verify_mode = ssl.CERT_NONE

    # Create an in-memory session ticket store for the proxy server to optimize reconnections
    session_ticket_store = SessionTicketStore()

    # NEW: CSV File setup
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
                    'Query_Type',
                    'Client_Query_Receive_Prep_s',
                    'Upstream_Connection_Establishment_s',
                    'Upstream_Query_Transmission_Setup_s',
                    'Wait_for_Upstream_Encrypted_Response_s',
                    'Client_Response_Transmit_Setup_s',
                    'TOTAL_Time_s'
                ])
            logging.info(f"Timing data will be logged to {args.timing_log}")
        except Exception as e:
            logging.error(f"Could not open CSV file {args.timing_log}: {e}")
            csv_writer = None
    # END NEW: CSV File setup

    try:
        # Run the main asynchronous function to start the proxy
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
                csv_writer=csv_writer, # Passed writer
            )
        )
    except KeyboardInterrupt:
        logger.info("DNS over QUIC proxy stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"DNS over QUIC proxy encountered a fatal error: {e}", exc_info=True)
    finally: # NEW: Close CSV file
        if csv_file:
            csv_file.close()