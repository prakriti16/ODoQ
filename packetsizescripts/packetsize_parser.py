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
    summary_regex = re.compile(r"^\s*(\d+)\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+DNS\s+\d+\s+(.*)$")#capture the summary line (Packet No. and the full Info string), group 1 is Packet Number and group 2 is the full Info column content
    payload_regex = re.compile(r"^\s*UDP payload \((\d+)\s+bytes\)$") #capture the UDP payload length from the detail block in bytes
    a_record_info_regex = re.compile(
        r'\sA\s([a-zA-Z0-9\.\-]+)'        #literal sequence ' A ' (with surrounding spaces) followed by the Domain (Group 1)
        r'(?:\sA\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?' #resolved IPv4 address (optional, captured only in successful responses) (Group 2)
    )
    results = []
    current_packet = None

    for line in log_content.splitlines():
        summary_match = summary_regex.match(line) #check for Summary Line (Start of a new packet record)
        if summary_match: #check if this line specifically relates to an A record (IPv4 Address query/response)
            pkt_no = int(summary_match.group(1))
            info_string = summary_match.group(2).strip()
            a_info_match = a_record_info_regex.search(info_string) 
            if not a_info_match: #else skip
                current_packet = None
                continue
            domain = a_info_match.group(1).strip(',.OPT')
            resolved_ip = a_info_match.group(2) if a_info_match.group(2) else 'N/A'
            pkt_type = "Query" if "Standard query" in info_string and "response" not in info_string else "Response" #packet type
            current_packet = {
                'No.': pkt_no,
                'Type': pkt_type,
                'Domain_Queried': domain,
                'Resolved_IP': resolved_ip,
                'Payload_Length': 0  #placeholder filled by the next step
            }
            continue
        payload_match = payload_regex.match(line) #check for UDP Payload Line
        if payload_match and current_packet:
            current_packet['Payload_Length'] = int(payload_match.group(1)) #payload length for the currently tracked A record packet
            results.append(current_packet) #reset for the next packet
            current_packet = None
            continue
    return results

def write_to_csv(data, filename="wireshark_dns_a_payloads.csv"):
    """Writes the extracted A record data to a CSV file."""
    if not data:
        print("No A record data to write.")
        return
    fieldnames = ['No.','Type','Domain_Queried','Resolved_IP','Payload_Length']
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Successfully wrote {len(data)} A record packets to {filename}")
    except Exception as e:
        print(f"An error occurred while writing to CSV: {e}")
try:
    with open("odohcloudflare.txt", 'r', encoding='utf-8') as f:
        log_data = f.read()
except FileNotFoundError:
    print("Error: 'your_wireshark_output.txt' not found.")
    exit()
extracted_data = parse_wireshark_log(log_data)
output_filename = "odohcloudflare.csv"
write_to_csv(extracted_data, output_filename)

