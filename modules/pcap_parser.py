#!/usr/bin/env python3

import os
import time
from modules.pcap_parser import PCAPAnalyzer

PCAP_DIR = "capture"
POLL_INTERVAL = 1
processed_pcaps = set()


def analyze_pcap(pcap_path):
    print(f"\n[+] Analyzing PCAP: {pcap_path}")

    analyzer = PCAPAnalyzer(output_dir="data")

    # ✅ CORRECT METHOD
    df = analyzer.analyze_pcap(pcap_path)

    if df.empty:
        print("⚠️ No flows extracted")
        return

    stats = analyzer.get_flow_statistics(df)

    print("[*] Live Analysis Output")
    print(f"    Total Flows        : {stats.get('total_flows', 0)}")
    print(f"    Suspected Tor      : {stats.get('suspected_tor_flows', 0)}")
    print(f"    Total Packets      : {stats.get('total_packets', 0)}")
    print(f"    Total Bytes        : {stats.get('total_bytes', 0)}")
    print(f"    Avg Tor Confidence : {stats.get('avg_tor_confidence', 0)}")
    print(f"    Unique Src IPs     : {stats.get('unique_src_ips', 0)}")
    print(f"    Unique Dst IPs     : {stats.get('unique_dst_ips', 0)}")
    print("-" * 55)


def main():
    print("[*] Live Tor Traffic Analysis Started")

    os.makedirs(PCAP_DIR, exist_ok=True)

    while True:
        for filename in sorted(os.listdir(PCAP_DIR)):
            if not filename.endswith(".pcap"):
                continue

            if filename in processed_pcaps:
                continue

            full_path = os.path.join(PCAP_DIR, filename)

            if os.path.getsize(full_path) == 0:
                continue

            analyze_pcap(full_path)
            processed_pcaps.add(filename)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Live pipeline stopped")
