import re
import csv
import io

def parse_wireshark_log(log_content):
    """
    Parses Wireshark text output to extract A record DNS packet details
    and the FRAME LENGTH (full packet size on wire).
    """

    summary_regex = re.compile(
        r"^\s*(\d+)\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+DNS\s+\d+\s+(.*)$"
    )

    # NEW: Extract Frame Length
    frame_len_regex = re.compile(r"^\s*Frame Length:\s+(\d+)\s+bytes")

    a_record_info_regex = re.compile(
        r'\sA\s([a-zA-Z0-9\.\-]+)'
        r'(?:\sA\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?'
    )

    results = []
    current_packet = None

    for line in log_content.splitlines():

        # --- Packet summary line ---
        summary_match = summary_regex.match(line)
        if summary_match:
            pkt_no = int(summary_match.group(1))
            info_string = summary_match.group(2).strip()

            a_info_match = a_record_info_regex.search(info_string)
            if not a_info_match:
                current_packet = None
                continue

            domain = a_info_match.group(1).strip(',.OPT')
            resolved_ip = a_info_match.group(2) if a_info_match.group(2) else 'N/A'

            pkt_type = "Query" if "Standard query" in info_string and "response" not in info_string else "Response"

            # Start new packet record
            current_packet = {
                'No.': pkt_no,
                'Type': pkt_type,
                'Domain_Queried': domain,
                'Resolved_IP': resolved_ip,
                'Frame_Length': 0,   # <-- new field
            }
            continue

        # --- Frame Length line ---
        frame_match = frame_len_regex.match(line)
        if frame_match and current_packet:
            current_packet['Frame_Length'] = int(frame_match.group(1))
            results.append(current_packet)
            current_packet = None
            continue

    return results



def write_to_csv(data, filename="wireshark_dns_a_framelen.csv"):
    """Writes extracted A record DNS data to CSV."""
    if not data:
        print("No A record data to write.")
        return

    fieldnames = ['No.', 'Type', 'Domain_Queried', 'Resolved_IP', 'Frame_Length']

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Successfully wrote {len(data)} A-record packets to {filename}")
    except Exception as e:
        print(f"Error writing CSV: {e}")


filename="doq_quicaiortc"
# Load Wireshark text export file
try:
    with open(f"{filename}.txt", 'r', encoding='utf-8') as f:
        log_data = f.read()
except FileNotFoundError:
    print(f"Error: '{filename}.txt' not found.")
    exit()

# Parse & write CSV
extracted_data = parse_wireshark_log(log_data)
output_filename = f"{filename}.csv"
write_to_csv(extracted_data, output_filename)
