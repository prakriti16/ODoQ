import argparse
import asyncio
import logging
import struct
import time
from typing import Dict, Optional
import os # NEW
import csv # NEW

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import SessionTicket
from dnslib.dns import DNSRecord

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv)) #Use the extracted client_symmetric_key here
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, encrypted_payload):
    iv = encrypted_payload[:16]
    ciphertext = encrypted_payload[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

class DnsServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, priv_key=None, csv_writer=None, **kwargs): # MODIFIED
        super().__init__(*args, **kwargs)
        # Load private key for decrypting AES key
        self.priv_key = priv_key
        self.csv_writer = csv_writer # NEW

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            try:
                data = event.data
                print("server received encrypted query:", data)
                t1 = time.time()

                # Unpack the length of the encrypted AES key
                aes_key_len = struct.unpack("!H", data[:2])[0]
                encrypted_aes_key = data[2:2+aes_key_len]
                encrypted_payload = data[2+aes_key_len:]

                # Decrypt AES key with the private key
                aes_key = self.priv_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Decrypt the payload using the decrypted ephemeral AES key
                decrypted_payload = aes_decrypt(aes_key, encrypted_payload)

                # Extract client symmetric key (first 16 bytes)
                client_symmetric_key = decrypted_payload[:16]

                # Extract nonce (next 8 bytes)
                nonce_bytes = decrypted_payload[16:24]
                nonce = struct.unpack("!Q", nonce_bytes)[0]
                

                # Extract actual DNS query (remaining bytes)
                query_bytes = decrypted_payload[24:]
                t2 = time.time()
                print(f"Server extracted client symmetric key: {client_symmetric_key.hex()}")
                print(f"Server extracted nonce: {nonce}")
                # Parse query
                query = DNSRecord.parse(query_bytes)
                t3 = time.time()
                
                query_name = str(query.q.qname) # Extract query name for logging

                # Perform DNS lookup (forward to upstream resolver)
                answer_bytes = query.send(args.resolver, 53)
                t4 = time.time()

                # Prepend nonce to answer
                response_payload = nonce_bytes + answer_bytes

                # Encrypt the response using the client's symmetric key
                encrypted_answer = aes_encrypt(client_symmetric_key, response_payload)
                t5 = time.time()

                print("server sent encrypted answer:", encrypted_answer)

                # Send the encrypted answer back
                t6 = time.time()
                self._quic.send_stream_data(event.stream_id, encrypted_answer, end_stream=True)
                t7 = time.time()
                
                t_decrypt = t2-t1
                t_lookup = t4-t3
                t_encrypt = t5-t4
                t_transmit = t7-t6
                t_total = t_decrypt + t_lookup + t_encrypt + t_transmit + (t3-t2) + (t6-t5)

                print("\n--- Server Timing Breakdown ---")
                print("{:<30} {:<10}".format("Operation", "Time (s)"))
                print("{:<30} {:<10.6f}".format("Query decryption & parsing", t_decrypt))
                print("{:<30} {:<10.6f}".format("DNS lookup (local)", t_lookup))
                print("{:<30} {:<10.6f}".format("Answer encryption", t_encrypt))
                print("{:<30} {:<10.6f}".format("Answer transmission setup", t_transmit))
                print("{:<30} {:<10.6f}".format("TOTAL Server Handling Time (s)", t_total)) # Added total time
                print("-------------------------------")
                
                # NEW: Write to CSV
                if self.csv_writer:
                    self.csv_writer.writerow([
                        query_name,
                        f"{t_decrypt:.6f}",
                        f"{t_lookup:.6f}",
                        f"{t_encrypt:.6f}",
                        f"{t_transmit:.6f}",
                        f"{t_total:.6f}"
                    ])
                    self._quic.parent_connection.csv_file.flush() # Ensure data is written immediately

            except Exception as e:
                logging.error(f"Error handling encrypted query: {e}")

class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)

async def main(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
    priv_key, # Passed in main for protocol creation
    csv_writer, # NEW
) -> None:
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: DnsServerProtocol(*args, priv_key=priv_key, csv_writer=csv_writer, **kwargs), # MODIFIED
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    await asyncio.Future()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC server (encrypted)")
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=853,
        help="listen on the specified port (defaults to 853)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        required=True,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--resolver",
        type=str,
        default="8.8.8.8",
        help="Upstream Classic DNS resolver to use",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "--timing-log", # NEW
        type=str,
        default=None,
        help="Path to a CSV file to log server timing analysis.", # NEW
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.quic_log:
        quic_logger = QuicFileLogger(args.quic_log)
    else:
        quic_logger = None

    configuration = QuicConfiguration(
        alpn_protocols=["doq"],
        is_client=False,
        quic_logger=quic_logger,
    )

    configuration.load_cert_chain(args.certificate, args.private_key)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    priv_key = None
    if args.private_key:
        with open(args.private_key, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)

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
                    'Domain_Queried',
                    'Query_Decryption_Parsing_s',
                    'DNS_Lookup_s',
                    'Answer_Encryption_s',
                    'Answer_Transmission_Setup_s',
                    'TOTAL_Time_s'
                ])
            logging.info(f"Timing data will be logged to {args.timing_log}")
        except Exception as e:
            logging.error(f"Could not open CSV file {args.timing_log}: {e}")
            csv_writer = None
    # END NEW: CSV File setup

    try:
        asyncio.run(
            main(
                host=args.host,
                port=args.port,
                configuration=configuration,
                session_ticket_store=SessionTicketStore(),
                retry=args.retry,
                priv_key=priv_key, # Passed key
                csv_writer=csv_writer, # Passed writer
            )
        )
    except KeyboardInterrupt:
        pass
    finally: # NEW: Close CSV file
        if csv_file:
            csv_file.close()
