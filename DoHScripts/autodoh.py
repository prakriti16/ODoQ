import subprocess
import time

domains_to_test = [
    "quic.aiortc.org",
    "google.com",
    "dns.adguard.com",
    "youtube.com",
    "facebook.com",
    "wikipedia.org",
    "instagram.com",
    "bing.com",
    "reddit.com",
    "x.com"
]

SERVER_IP = "10.230.3.93"
SERVER_PORT = "4433"
CA_CERT = "server.pem"
TIMING_LOG = "dec4doq.csv"

NUM_RUNS = 100

for domain in domains_to_test:
    print(f"\n=== Testing domain: {domain} ===")

    for i in range(NUM_RUNS):
        print(f"  Run {i+1}/{NUM_RUNS}...")

        cmd = [
            "python3", "doh_client.py",
            "--server", SERVER_IP,
            "--server-port", SERVER_PORT,
            "--query-name", domain,
            "--query-type", "A",
            "--ca-certs", CA_CERT,
            "-v",
            "--timing-log", TIMING_LOG
        ]

        try:
            subprocess.run(cmd, check=False)
        except Exception as e:
            print(f"Error during run {i+1}: {e}")

        # short sleep to avoid overwhelming the resolver
        time.sleep(0.05)

print("\n=== All tests complete! ===")
