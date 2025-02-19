#!/usr/bin/env python3

import csv
import random
import argparse

def generate_ip(base, count):
    """Generate valid IPs based on a base address."""
    ips = []
    for i in range(count):
        if base.startswith("192"):
            ip = f"192.168.{i // 256 % 256}.{i % 256}"
        elif base.startswith("2001"):
            ip = f"2001:4860:4860::{i % 65535:x}"
        elif base == "invalid":
            ip = f"invalid_ip_{i}"
        else:
            ip = f"{base}.{i // 256 % 256}.{i % 256}"
        ips.append(ip)
    return ips

def generate_test_csv(total_ips):
    random.seed(42)
    public_count = int(total_ips * 0.3)
    private_count = int(total_ips * 0.6)
    invalid_count = int(total_ips * 0.08)
    duplicate_count = int(total_ips * 0.02)

    total_generated = public_count + private_count + invalid_count + duplicate_count
    if total_generated < total_ips:
        private_count += (total_ips - total_generated)
    elif total_generated > total_ips:
        private_count -= (total_generated - total_ips)

    public_ips = generate_ip("8.8", public_count // 2) + generate_ip("1.1", public_count // 2)
    private_ips = generate_ip("192.168", private_count)
    invalid_ips = generate_ip("invalid", invalid_count)
    duplicate_ips = random.sample(public_ips + private_ips, duplicate_count)

    all_ips = public_ips + private_ips + invalid_ips + duplicate_ips
    random.shuffle(all_ips)

    if len(all_ips) > total_ips:
        all_ips = all_ips[:total_ips]
    elif len(all_ips) < total_ips:
        all_ips.extend(generate_ip("10.0", total_ips - len(all_ips)))

    with open(f'test_{total_ips}_ips.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP"])
        for ip in all_ips:
            writer.writerow([ip])

    print(f"Generated 'test_{total_ips}_ips.csv' with {len(all_ips)} IPs")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a test CSV with a specified number of IPs.")
    parser.add_argument("--num-ips", type=int, default=5000, help="Number of IPs (default: 5000)")
    args = parser.parse_args()
    generate_test_csv(args.num_ips)