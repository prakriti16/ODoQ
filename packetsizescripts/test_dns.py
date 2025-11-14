import subprocess
import re
import os
import time,csv
from typing import List, Dict, Any
# --- Configuration ---
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

PROXY_EXECUTABLE = r".\dnscrypt-proxy.exe"

# FIX APPLIED: Listener address updated to use the new port 8153
LISTENER_ADDRESS = "@0.0.0.0:8153"
LOG_FILE_PATH = "query.log"
DNS_RECORD_TYPES = ['A']

# Regex to robustly capture the domain name and log details
LOG_PATTERN = re.compile(
    r"^\[.*?\]\s+127\.0\.0\.1\s+([^\s]+)\s+(" + "|".join(DNS_RECORD_TYPES) + r")\s+PASS\s+(\d+)ms"
)

# --- Functions ---

def run_resolution_command(domain: str):
    """Runs the dnscrypt-proxy -resolve command for a given domain."""
    command = [
        PROXY_EXECUTABLE,
        "-resolve",
        f"{domain}",
        # Passes the correct 0.0.0.0:8153 address to the resolver
        LISTENER_ADDRESS 
    ]

    try:
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=15 
        )
        return True 

    except FileNotFoundError:
        print(f"ERROR: Proxy executable not found at {PROXY_EXECUTABLE}")
        return False
    except subprocess.TimeoutExpired:
        print(f"WARNING: Resolution command timed out for {domain}.")
        return False
    except Exception as e:
        print(f"ANOTHER ERROR during command execution for {domain}: {e}")
        return False


def parse_latest_log_times(domain: str):
    """Reads the log file, finds the latest CNAME and A times for the domain."""
    if not os.path.exists(LOG_FILE_PATH):
        print(f"ERROR: Log file not found at {LOG_FILE_PATH}")
        return None

    with open(LOG_FILE_PATH, 'r') as f:
        lines = f.readlines()

    times = {qtype: None for qtype in DNS_RECORD_TYPES}

    for line in reversed(lines):
        match = LOG_PATTERN.search(line)
        
        if match:
            # Group 1: Domain, Group 2: Query Type, Group 3: Time
            log_domain, qtype, time_ms_str = match.groups()
            
            if log_domain == domain:
                
                if times[qtype] is None:
                    times[qtype] = int(time_ms_str)
                
                if all(t is not None for t in times.values()):
                    break
    
    return times
def parse_all_log_times_to_csv(domain: str) -> None:
    """
    Reads the log file, finds ALL CNAME and A times for the domain,
    and writes the collected data to 'output.csv'.
    
    Args:
        domain: The domain string to search for in the log.
    """
    
    if not os.path.exists(LOG_FILE_PATH):
        print(f"❌ ERROR: Log file not found at {LOG_FILE_PATH}")
        return

    # List to hold all matching log records
    all_records: List[Dict[str, Any]] = []

    print(f"🔎 Processing log file: {LOG_FILE_PATH}")
    
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            # Iterate forward through all lines (no 'reversed(lines)')
            for line in f:
                match = LOG_PATTERN.search(line)
                
                if match:
                    # Group 1: Domain, Group 2: Query Type, Group 3: Time
                    log_domain, qtype, time_ms_str = match.groups()
                    
                    if log_domain == domain and qtype in DNS_RECORD_TYPES:
                        
                        # Collect the data for this line
                        record = {
                            'Domain': log_domain,
                            'QueryType': qtype,
                            'Time_ms': int(time_ms_str),
                            'RawLine': line.strip() # Include the full line for context
                        }
                        all_records.append(record)
    
    except IOError as e:
        print(f"❌ ERROR reading log file: {e}")
        return

    if not all_records:
        print(f"⚠️ WARNING: No records found for domain '{domain}' with types {DNS_RECORD_TYPES}.")
        return

    # --- Write Results to CSV ---
    OUTPUT_FILE_PATH = 'output1.csv'
    
    try:
        # Define the headers for the CSV file
        fieldnames = ['Domain', 'QueryType', 'Time_ms', 'RawLine']
        
        with open(OUTPUT_FILE_PATH, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write the header row
            writer.writeheader()
            
            # Write all collected records
            writer.writerows(all_records)
            
        print(f"✅ Successfully wrote {len(all_records)} records to {OUTPUT_FILE_PATH}")

    except IOError as e:
        print(f"❌ ERROR writing to CSV file: {e}")

def calculate_total_time(times: dict):
    """Calculates Total Resolution Time = T_A"""
    T_A = times.get('A', 0)

    T_A = T_A if T_A is not None else 0
    
    # Calculate Total Time (Sequential CNAME + A)
    total_time = T_A
    
    return total_time

# --- Main Execution ---

if __name__ == "__main__":
    print("--- Starting Automated DNS Resolution Tests ---")
    print(f"Proxy configured for: {LISTENER_ADDRESS}. Results will be parsed from {LOG_FILE_PATH}.\n")

    final_results = []
    
    print("NOTE: Clearing proxy cache by waiting 5 seconds before starting tests...")
    time.sleep(5)

    for domain in domains_to_test:
        # parse_all_log_times_to_csv(domain)
        print(f"Testing {domain:<20}...", end="", flush=True)

        if not run_resolution_command(domain):
            final_results.append((domain, "Error/Timeout"))
            print("FAILED.")
            continue
        
        time.sleep(0.1) 
        
        latest_times = parse_latest_log_times(domain)
        
        if latest_times and any(t is not None for t in latest_times.values()):
            a_time = calculate_total_time(latest_times)
            
            status = f"A: {a_time}ms"
            print(f"DONE. A Time: {a_time}ms")
            final_results.append((domain, status))
        else:
            print("FAILED. No relevant log entries found.")
            final_results.append((domain, "FAILED. No relevant log entries."))


    print("\n" + "="*70)
    print("--- FINAL RESOLUTION TIME SUMMARY (CNAME + A) ---")
    print("="*70)
    print("Domain               | A Time          ")
    print("-" * 70)
    for domain, status in final_results:
        print(f"{domain:<20} | {status}") 
    print("="*70)

    