import argparse
import asyncio
import csv
import logging
import pickle
import ssl
import struct
import time
import os
from typing import Optional, cast

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger
from dnslib.dns import QTYPE, DNSHeader, DNSQuestion, DNSRecord

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate


logger = logging.getLogger("client")

def generate_aes_key():
    # Used for the ephemeral transaction key
    return os.urandom(32)

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

class DnsClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args,server_pubkey=None, csv_writer=None,**kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.server_pubkey = server_pubkey
        self.csv_writer=csv_writer
        self._ack_waiter: Optional[asyncio.Future[bytes]] = None

    async def query(self, query_name: str, query_type: str) -> bytes:
        t1 = time.time()
        # serialize DNS query
        query = DNSRecord(
            header=DNSHeader(id=0),
            q=DNSQuestion(query_name, getattr(QTYPE, query_type)),
        )
        query_bytes = bytes(query.pack())

        # Generate client symmetric key
        client_symmetric_key = os.urandom(16)
        

        # --- NEW: Generate nonce (timestamp) ---
        nonce = int(time.time() * 1000)  # milliseconds
        nonce_bytes = struct.pack("!Q", nonce)  # 8-byte unsigned long long
        

        # Prepend key + nonce to query
        plaintext_payload = client_symmetric_key + nonce_bytes + query_bytes

        # Generate ephemeral AES key
        aes_key = generate_aes_key()

        # Encrypt payload
        encrypted_payload = aes_encrypt(aes_key, plaintext_payload)

        # Encrypt AES key with server’s public key
        encrypted_aes_key = self.server_pubkey.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send
        data = struct.pack("!H", len(encrypted_aes_key)) + encrypted_aes_key + encrypted_payload
        
        t2 = time.time()
        print(f"Generated client symmetric key for response: {client_symmetric_key.hex()}")
        print(f"Generated nonce: {nonce}")
        print("Encrypted query sent from client:", data)
        t21 =time.time()

        # send query and wait for answer
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()
        t3 = time.time()
        response = await asyncio.shield(waiter)
        print("Encrypted response size:",len(response),"bytes")
        decrypted_response = aes_decrypt(client_symmetric_key, response)
        print("Decrypted msg size:",len(decrypted_response),"bytes")
        t4 = time.time()

        # Extract nonce from server’s response
        resp_nonce = struct.unpack("!Q", decrypted_response[:8])[0]
        dns_bytes = decrypted_response[8:]  # remaining is DNS payload

        if resp_nonce != nonce:
            raise ValueError(f"Nonce mismatch! Sent {nonce}, got {resp_nonce}")
        else:
            print(f"Nonce verified: {resp_nonce}")
        # Verify domain name in response 
        try:
            answer = DNSRecord.parse(dns_bytes)
            # Access the question's QNAME directly from the 'q' attribute.
            # .q is a DNSQuestion object, not a list of questions.
            # Use .qname.idna() to get the domain name string for comparison.
            if answer.q and answer.q.qname.idna() != query_name:
                raise ValueError(
                    f"Domain name mismatch! Requested '{query_name}', "
                    f"but response contains '{answer.q.qname.idna()}'"
                )
            else:
                print(f"Domain name verified: {query_name}")
        except Exception as e:
            # Re-raise or handle DNS parsing errors if they occur here
            print(f"Warning: Could not parse or verify domain name: {e}")
            pass # Continue if parsing fails, but warn the user.
           
        t5=time.time()
        print("client received encrypted answer:", response)
        print("\n--- Client Timing Breakdown ---")
        print("{:<30} {:<10}".format("Operation", "Time (s)"))
        print("{:<30} {:<10.6f}".format("Query packet creation", t2-t1))
        print("{:<30} {:<10.6f}".format("Query transmission setup", t3-t21))
        print("{:<30} {:<10.6f}".format("Wait for encrypted response", t4-t3))
        print("{:<30} {:<10.6f}".format("Verifying nonce and domain", t5-t4))
        print("-------------------------------")
        if self.csv_writer:
            self.csv_writer.writerow([query_name,f"{t2-t1:.6f}",f"{t3-t21:.6f}",f"{t4-t3:.6f}",f"{t5-t4:.6f}",f"{t5-t21+t2-t1:.6f}"])
        return dns_bytes


    def quic_event_received(self, event: QuicEvent) -> None:
        # SIMPLIFIED LOGIC
        waiter = self._ack_waiter
        if waiter is not None and not waiter.done():
            if isinstance(event, StreamDataReceived):
                self._ack_waiter = None
                waiter.set_result(event.data)

def save_session_ticket(ticket):
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)

async def main(
    configuration: QuicConfiguration,
    host: str,
    port: int,
    query_name: str,
    query_type: str,
    server_cert: str,
    count: int, 
    timing_log_file: str
) -> None:
    # Load server public key from certificate
    try:
        # BUG FIX: Use the server_cert argument instead of a hardcoded filename
        with open(server_cert,"rb") as f1:
            cert_data=f1.read()
        cert=load_pem_x509_certificate(cert_data)
        server_pubkey=cert.public_key()
    except Exception as e:
        logger.error(f"Failed to load server public key from '{server_cert}': {e}")
        return
    
    csv_file = None
    csv_writer = None
    if timing_log_file:
        file_exists = os.path.exists(timing_log_file)
        file_is_empty = not file_exists or os.path.getsize(timing_log_file) == 0
        try:
            # Open the CSV file and write the header
            csv_file = open(timing_log_file, 'a', newline='')
            csv_writer = csv.writer(csv_file)
            if file_is_empty:
                csv_writer.writerow(['Domain queried','Query_Packet_Creation_s','Transmission_Setup_s','Wait_for_Encrypted_Response_s','Response_Decryption_s','Total_Time_s'])
            logger.info(f"Timing data will be logged to {timing_log_file}")
        except Exception as e:
            logger.error(f"Could not open CSV file {timing_log_file}: {e}")
            csv_writer = None # Disable logging if error occurs
    
    logger.debug(f"Connecting to {host}:{port}")
    async with connect(
        host,
        port,
        configuration=configuration,
        session_ticket_handler=save_session_ticket,
        create_protocol=lambda *a, **kw: DnsClientProtocol(*a, server_pubkey=server_pubkey,csv_writer=csv_writer, **kw),
    ) as client:
        client = cast(DnsClientProtocol, client)
        logger.debug("Sending encrypted DNS query")
        answer_bytes = await client.query(query_name, query_type)
        try:
            answer = DNSRecord.parse(answer_bytes)
            logger.info("Received DNS answer\n%s" % answer)
        except Exception as e:
            logger.error("Failed to parse DNS answer: %s", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC client (encrypted)")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="The remote peer's host name or IP address",
    )
    parser.add_argument(
        "--port", type=int, default=853, help="The remote peer's port number"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--server-cert",
        type=str,
        required=True,
        help="Path to the server certificate (.pem) containing the public key"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument("--query-name", required=True, help="Domain to query")
    parser.add_argument("--query-type", default="A", help="The DNS query type to send")
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
        "-c",
        "--count",
        type=int,
        default=1,
        help="Number of DNS queries to send for timing (default: 1).", 
    )
    parser.add_argument(
        "--timing-log",
        type=str,
        default=None,
        help="Path to a CSV file to log iteration number and query time.", #For logging timing analysis
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True)
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
            logger.debug(f"Unable to read {args.session_ticket}")
            pass
    else:
        logger.debug("No session ticket defined...")

    asyncio.run(
        main(
            configuration=configuration,
            host=args.host,
            port=args.port,
            query_name=args.query_name,
            query_type=args.query_type,
            server_cert=args.server_cert,
            count=args.count,                  
            timing_log_file=args.timing_log
        )
    )
