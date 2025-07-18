#!/usr/bin/env python3

import argparse
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def get_http_code(proxy, target, port, delay_ms=0):
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    url = f"http://{target}:{port}"
    try:
        result = subprocess.run(
            ["curl", "-x", f"http://{proxy}", url, "-m", "3", "-s", "-o", "/dev/null", "-w", "%{http_code}"],
            capture_output=True,
            text=True,
        )
        return port, result.stdout.strip()
    except Exception:
        return port, "000"

def parse_args():
    parser = argparse.ArgumentParser(description="Scan open ports on a target via a Squid proxy.")
    parser.add_argument("--proxy", required=True, help="Squid proxy in format IP:PORT (e.g. 10.10.10.10:3128)")
    parser.add_argument("--target", required=True, help="Target host to scan (e.g. 10.10.10.10)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--top", action="store_true", help="Scan first 1000 ports (1–1024)")
    group.add_argument("--full", action="store_true", help="Scan full port range (1–65535)")
    
    parser.add_argument("--random", action="store_true", help="Scan ports in random order")
    parser.add_argument("--threads", type=int, default=50, help="Number of parallel threads (default: 50)")
    parser.add_argument("--delay", type=int, default=0, help="Optional delay in milliseconds between requests (default: 0)")
    return parser.parse_args()

def main():
    args = parse_args()

    port_range = range(1, 1025) if args.top else range(1, 65536)
    ports = list(port_range)
    if args.random:
        random.shuffle(ports)

    print(f"[*] Scanning {args.target} via Squid proxy at {args.proxy}")
    print(f"[*] Port range: {port_range.start}-{port_range.stop - 1} {'(randomized)' if args.random else ''}")
    print(f"[*] Using {args.threads} threads with {args.delay} ms delay between requests\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_port = {
            executor.submit(get_http_code, args.proxy, args.target, port, args.delay): port
            for port in ports
        }

        for future in tqdm(as_completed(future_to_port), total=len(ports), desc="Scanning", unit="port"):
            port, code = future.result()
            if code not in ("000", "403", "503"):
                results.append((port, code))
                print(f"[+] Port {port} returned HTTP {code} (possibly allowed)")

    print("\n[*] Scan complete.")
    if results:
        print("\n[+] Summary of accessible ports:")
        for port, code in sorted(results):
            print(f"    - Port {port}: HTTP {code}")
    else:
        print("[-] No accessible ports found.")

if __name__ == "__main__":
    main()

