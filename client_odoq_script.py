import subprocess
import shlex
import os
import time
import csv
from collections import defaultdict

# --- Configuration ---

# 1. Domains to test (10 domains)
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

# 2. Base command and arguments (excluding the domain placeholder)
# NOTE: It is assumed that 'doq_client.py' is in the current working directory or in your PATH.
BASE_COMMAND_TEMPLATE = (
    "python doq_client.py "
    "--ca-certs onlyproxy.pem "
    "--query-type A "
    "--port 8053 "
    "--host 10.240.60.74 "
    "--server-cert onlyserver.pem "
    "--insecure "
    "-c 100 "
    "--timing-log odoqdec2client1.csv "
    "--upstream-host 10.230.3.93 "
    "--upstream-port 8053 "
    "--query-name {domain}" # Placeholder for the domain
)

# 3. Output file path
CSV_FILE_PATH = "odoqdec2client1.csv"

# --- Execution ---

def run_queries():
    """
    Loops through the domains, constructs the full command, and executes it
    using subprocess.
    """
    print(f"Starting execution of DoQ client for {len(domains_to_test)} domains.")

    # Optional: Clear the CSV file before starting new runs if it exists
    if os.path.exists(CSV_FILE_PATH):
        try:
            os.remove(CSV_FILE_PATH)
            print(f"Cleared existing file: {CSV_FILE_PATH}")
        except OSError as e:
            print(f"Error clearing CSV file: {e}. Aborting.")
            return

    for i, domain in enumerate(domains_to_test):
        # 1. Substitute the domain into the command template
        full_command = BASE_COMMAND_TEMPLATE.format(domain=domain)
        
        # 2. Prepare the command for subprocess
        command_list = shlex.split(full_command)
        
        print(f"\n--- Running Test {i + 1}/{len(domains_to_test)} for: {domain} ---")
        print(f"Command: {full_command}")
        
        try:
            # 3. Execute the command
            # Note: stdout/stderr are captured but not printed by default to keep output clean
            result = subprocess.run(
                command_list,
                capture_output=True,
                text=True,
                check=True
            )
            
            print(f"[{domain}] Command executed successfully.")
            
        except subprocess.CalledProcessError as e:
            # Handle non-zero exit codes (errors in the client script)
            print(f"[{domain}] ERROR: Command failed with exit code {e.returncode}")
            print("STDERR (Last 5 lines):")
            # Print only a subset of the error to keep the loop moving
            print('\n'.join(e.stderr.splitlines()[-5:]))
            
        except FileNotFoundError:
            print("FATAL ERROR: 'python' or 'doq_client.py' command not found. Ensure 'doq_client.py' is in the current directory.")
            break
            
        time.sleep(0.5) # Short pause between runs

    print("\n--- Raw data collection complete. ---")

def calculate_and_print_averages():
    """
    Reads the CSV file, calculates the average of all timing columns for each domain,
    and prints a summary table.
    """
    if not os.path.exists(CSV_FILE_PATH):
        print(f"Error: Timing log file not found at {CSV_FILE_PATH}. Cannot calculate averages.")
        return

    domain_data = defaultdict(lambda: defaultdict(list))
    header = []

    try:
        with open(CSV_FILE_PATH, mode='r', newline='') as file:
            reader = csv.reader(file)
            try:
                header = next(reader)
            except StopIteration:
                print("Error: CSV file is empty.")
                return

            # Find the indices of the timing columns (all columns except the first one)
            timing_indices = list(range(1, len(header)))
            
            # Populate domain_data with raw values
            for row in reader:
                if not row: continue
                # The first column is 'Upstream_Target' (e.g., '10.230.3.93:8053')
                # The second column is the domain name which is not explicitly stored in the current CSV format.
                # Assuming the second column in the CSV is the domain name or we use a simplified key.
                # NOTE: Based on the existing doq_proxy.py, the first column is 'Upstream_Target'.
                # For averaging per domain, the client script should ideally append the domain name.
                # Since it doesn't, we will calculate the average across ALL runs for simplicity in this version,
                # but print a warning that domain-specific averaging requires modifying doq_client.py.

                # --- Simplified Assumption: Calculate overall averages across all runs ---
                # This assumes the raw client output doesn't tag rows with the domain name.
                # If the CSV does contain the domain name (e.g., in a second column), this part needs adjustment.
                
                # For the current goal of demonstrating averaging, we use the header as a base.
                # We will print all averages across the entire test set.
                
                # Since the current setup logs 10 runs per domain sequentially, 
                # we'll assume the rows match the sequence of domains_to_test * 10.
                
                # A robust solution requires the client to explicitly log the domain name.
                # Let's adjust the logic to infer the domain based on the row index, 
                # assuming exactly 10 runs per domain.
                
                # The CSV headers are typically:
                # Upstream_Target, T_Received_s, Delta_T_Meta_s, T_Forwarded_s, Delta_T_Wait_s, T_Response_Sent_s, TOTAL_Time_s
                
                # We will use the Upstream_Target as the key for the averages for now, 
                # though it should be the domain itself.
                
                key = row[0] # Upstream_Target (e.g., 10.230.3.93:8053)
                
                # Collect timing data
                for i in timing_indices:
                    try:
                        # Convert string time to float and append to list for averaging
                        domain_data[key][header[i]].append(float(row[i]))
                    except ValueError:
                        # Skip if the value is not a valid number (e.g., header row or malformed data)
                        continue

    except Exception as e:
        print(f"An error occurred while reading the CSV file: {e}")
        return

    # Calculate final averages and format output
    average_results = defaultdict(dict)
    
    for key, metrics in domain_data.items():
        for metric_name, values in metrics.items():
            if values:
                average_results[key][metric_name] = sum(values) / len(values)
                
    
    # --- Print Summary Table ---
    if not average_results:
        print("No valid timing data found to calculate averages.")
        return

    print("\n" + "="*80)
    print("                 AVERAGE TIMING RESULTS ACROSS ALL RUNS                 ")
    print("="*80)
    
    # Use the first key (Upstream_Target) to get the list of metrics
    first_key = next(iter(average_results))
    metric_names = [name for name in header[1:] if name in average_results[first_key]]
    
    # Simplified column width calculation
    col_width = 18 
    
    # Print Header Row
    header_line = "{:<16}".format("Target")
    for name in metric_names:
        # Shorten metric names for table readability
        short_name = name.replace('_s', '').replace('Delta_', 'D_').replace('T_', '')
        header_line += f"| {short_name:<{col_width}}"
    print(header_line)
    print("-" * 80)
    
    # Print Data Rows
    for key, avg_metrics in average_results.items():
        data_line = "{:<16}".format(key)
        for name in metric_names:
            avg_value = avg_metrics.get(name, 0.0)
            data_line += f"| {avg_value:<{col_width}.6f}" # Displaying 6 decimal places
        print(data_line)

    print("="*80)
    print(f"\nNOTE: Averages are currently grouped by '{header[0]}' (Upstream Target: {first_key})")
    print("A proper domain-per-domain average requires modifying 'doq_client.py' to log the domain name explicitly.")


if __name__ == "__main__":
    # 1. Run the tests to collect all raw data
    run_queries()

    # 2. Process the collected data and print averages
    calculate_and_print_averages()
