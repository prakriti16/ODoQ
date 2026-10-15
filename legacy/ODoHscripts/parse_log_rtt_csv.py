import re
import csv
from pathlib import Path

# === CONFIG: change these if you want ===
LOG_FILE = "odoh_cloudflare_rtt.log"
OUT_CSV  = "A_records_rtt.csv"

# Example line:
# [2025-12-04 17:19:58]  127.0.0.1  bing.com  AAAA  PASS  204ms  odoh-cloudflare
LINE_RE = re.compile(
    r"""^\[
        (?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})
        \]\s+
        (?P<client>\S+)\s+
        (?P<domain>\S+)\s+
        (?P<qtype>\S+)\s+
        (?P<status>\S+)\s+
        (?P<time_ms>\d+)ms\s+
        (?P<resolver>\S+)
        """,
    re.VERBOSE,
)

def main():
    log_path = Path(LOG_FILE)
    out_path = Path(OUT_CSV)

    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        return

    rows = []

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = LINE_RE.match(line)
            if not m:
                continue

            qtype = m.group("qtype")
            status = m.group("status")
            domain = m.group("domain")
            time_ms = int(m.group("time_ms"))

            # Keep ONLY A records
            if qtype != "A":
                continue

            # If you want only successful ones, uncomment this:
            # if status != "PASS":
            #     continue

            rows.append({
                "domain": domain,
                "rtt_ms": time_ms,
            })

    if not rows:
        print("No A records found in log.")
        return

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "rtt_ms"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} A-record RTTs to {out_path}")

if __name__ == "__main__":
    main()
