import re
import csv
import io

def parse_wireshark_log(log_content):
    """
    Parses Wireshark text output to extract A record DNS packet details and UDP payload length.
    Only extracts records that are queries or responses for A (IPv4 Address) records.

    Args:
        log_content (str): The complete content of the Wireshark text file.

    Returns:
        list: A list of dictionaries, where each dictionary represents an A record packet.
    """
    # Regex 1: Capture the summary line (Packet No. and the full Info string)
    # Group 1: Packet Number
    # Group 2: The full Info column content
    summary_regex = re.compile(r"^\s*(\d+)\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+DNS\s+\d+\s+(.*)$")

    # Regex 2: Capture the UDP payload length from the detail block
    # Group 1: Payload size in bytes
    payload_regex = re.compile(r"^\s*UDP payload \((\d+)\s+bytes\)$")

    # Regex 3: Specifically target A record information in the Info string for extraction.
    # We look for the literal sequence ' A ' (with surrounding spaces) followed by the domain.
    # Group 1: The Domain being queried/responded to (e.g., quic.aiortc.org)
    # Group 2: The resolved IPv4 address (optional, captured only in successful responses)
    a_record_info_regex = re.compile(
        r'\sA\s([a-zA-Z0-9\.\-]+)'        # Find " A " followed by the Domain (Group 1)
        r'(?:\sA\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?' # Optionally find " A " followed by an IP address (Group 2)
    )

    results = []
    current_packet = None

    for line in log_content.splitlines():
        # 1. Check for Summary Line (Start of a new packet record)
        summary_match = summary_regex.match(line)
        if summary_match:
            pkt_no = int(summary_match.group(1))
            info_string = summary_match.group(2).strip()

            # --- FILTERING LOGIC ---
            # Check if this line specifically relates to an A record (IPv4 Address query/response)
            a_info_match = a_record_info_regex.search(info_string)
            if not a_info_match:
                # If it's not an A record (e.g., TXT, PTR, AAAA), skip processing this packet
                current_packet = None
                continue
            # -----------------------

            # Extract data for A records
            domain = a_info_match.group(1).strip(',.OPT') # Clean up artifacts from the capture
            resolved_ip = a_info_match.group(2) if a_info_match.group(2) else 'N/A'

            # Determine packet type
            pkt_type = "Query" if "Standard query" in info_string and "response" not in info_string else "Response"

            current_packet = {
                'No.': pkt_no,
                'Type': pkt_type,
                'Domain_Queried': domain,
                'Resolved_IP': resolved_ip,
                'Payload_Length': 0  # Placeholder to be filled by the next step
            }
            continue

        # 2. Check for UDP Payload Line (Details section)
        payload_match = payload_regex.match(line)
        if payload_match and current_packet:
            # We found the payload length for the currently tracked A record packet
            current_packet['Payload_Length'] = int(payload_match.group(1))

            # Store the completed packet record and reset for the next packet
            results.append(current_packet)
            current_packet = None
            continue

    return results

def write_to_csv(data, filename="wireshark_dns_a_payloads.csv"):
    """Writes the extracted A record data to a CSV file."""
    if not data:
        print("No A record data to write.")
        return

    # Define the fields for the CSV header
    fieldnames = ['No.', 'Type', 'Domain_Queried', 'Resolved_IP', 'Payload_Length']

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Successfully wrote {len(data)} A record packets to {filename}")
    except Exception as e:
        print(f"An error occurred while writing to CSV: {e}")

# --- Example Usage ---
try:
    with open("odohcloudflare.txt", 'r', encoding='utf-8') as f:
        log_data = f.read()
except FileNotFoundError:
    print("Error: 'your_wireshark_output.txt' not found.")
    exit()

# 1. Parse the log content
extracted_data = parse_wireshark_log(log_data)

# 2. Write the results to a CSV file
output_filename = "odohcloudflare.csv"
write_to_csv(extracted_data, output_filename)