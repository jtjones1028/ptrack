#!/usr/bin/env python3

"""PTRack: A Reverse and Forward DNS Lookup Tool.

Analyzes IP addresses from a CSV file, performing reverse DNS (PTR) lookups
and optional forward (A/AAAA) lookups. Outputs results in JSON or CSV format,
optimized for speed and scalability with threading and caching.
"""

import sys
import csv
import json
import argparse
import logging
from pathlib import Path
import dns.resolver
import dns.exception
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import time
import os
from datetime import datetime, UTC
import io
import tempfile

# Version of the tool
__version__ = "1.0.0"

# Ensure consistent UTF-8 encoding for cross-platform compatibility
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Configure logging with a timestamped format
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(funcName)s: %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

def reverse_dns_lookup(ip_obj, resolver, max_retries=1):
    """Perform a reverse DNS (PTR) lookup for an IP address.

    Args:
        ip_obj: An ipaddress.ip_address object representing the IP.
        resolver: A dns.resolver.Resolver object for DNS queries.
        max_retries: Number of retry attempts for failed lookups (default: 1).

    Returns:
        List of FQDNs if successful, None if no records or all retries fail.
    """
    logger.debug(f"Entering reverse_dns_lookup for {ip_obj}")
    start_time = time.time()
    for attempt in range(max_retries):
        try:
            ptr_query = ip_obj.reverse_pointer
            response = resolver.resolve(ptr_query, 'PTR')
            fqdn_dict = {}
            for rr in response.rrset:
                fqdn = rr.to_text().rstrip('.')
                fqdn_lower = fqdn.lower()
                if fqdn_lower not in fqdn_dict:  # Avoid duplicates
                    fqdn_dict[fqdn_lower] = fqdn
            fqdns = sorted(fqdn_dict.values(), key=str.lower)
            logger.debug(f"Reverse DNS lookup succeeded for {ip_obj}: {fqdns}")
            logger.info(f"Reverse lookup for {ip_obj} took {time.time() - start_time:.2f}s")
            return fqdns
        except dns.exception.DNSException as e:
            logger.debug(f"Attempt {attempt + 1} failed for {ip_obj}: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)  # Fixed 1s delay between retries
            else:
                logger.debug(f"Reverse DNS lookup failed for {ip_obj} after {max_retries} attempts")
                return None
    logger.info(f"Reverse lookup for {ip_obj} took {time.time() - start_time:.2f}s (failed)")
    return None

def get_associated_ips(fqdns, resolver, verbose=False, max_retries=1):
    """Perform forward DNS (A and AAAA) lookups for a list of FQDNs.

    Args:
        fqdns: List of fully qualified domain names to query.
        resolver: A dns.resolver.Resolver object for DNS queries.
        verbose: If True, include verbose data like CNAMEs (default: False).
        max_retries: Number of retry attempts for failed lookups (default: 1).

    Returns:
        Tuple of (IPv4 list, IPv6 list, verbose data dict).
    """
    logger.debug(f"Entering get_associated_ips for {fqdns}")
    start_time = time.time()
    ipv4_set = set()
    ipv6_set = set()
    verbose_data = {} if verbose else None

    for fqdn in fqdns:
        current_name = fqdn
        while True:  # Resolve CNAME chain
            try:
                cname_response = resolver.resolve(current_name, 'CNAME')
                current_name = cname_response.rrset[0].to_text().rstrip('.')
                if verbose:
                    verbose_data.setdefault(fqdn, []).append(f"CNAME: {current_name}")
            except dns.exception.DNSException:
                break

        for attempt in range(max_retries):  # A records
            try:
                a_records = resolver.resolve(current_name, 'A')
                for rr in a_records:
                    ipv4_set.add(str(rr))
                break
            except dns.exception.DNSException as e:
                logger.debug(f"A lookup attempt {attempt + 1} failed for {current_name}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    break

        for attempt in range(max_retries):  # AAAA records
            try:
                aaaa_records = resolver.resolve(current_name, 'AAAA')
                for rr in aaaa_records:
                    ipv6_set.add(str(rr))
                break
            except dns.exception.DNSException as e:
                logger.debug(f"AAAA lookup attempt {attempt + 1} failed for {current_name}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    break

    ipv4_list = sorted(ipv4_set)
    ipv6_list = sorted(ipv6_set)
    logger.info(f"Forward lookup for {fqdns} took {time.time() - start_time:.2f}s")
    logger.debug(f"Exiting get_associated_ips with IPv4: {ipv4_list}, IPv6: {ipv6_list}")
    return ipv4_list, ipv6_list, verbose_data

def process_ip(ip, resolver, cached_data, no_forward=False, verbose=False):
    """Process a single IP, checking cache or performing DNS lookups.

    Args:
        ip: String IP address to process.
        resolver: A dns.resolver.Resolver object for DNS queries.
        cached_data: Dict of cached IP results.
        no_forward: If True, skip forward lookups (default: False).
        verbose: If True, include verbose DNS data (default: False).

    Returns:
        Tuple of (IP string, result dict).
    """
    logger.debug(f"Entering process_ip for {ip}")
    start_time = time.time()
    
    if ip in cached_data:
        logger.info(f"Cache hit for {ip}")
        return ip, cached_data[ip]

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        result = {
            "status": "invalid",
            "fqdns": [],
            "associated_ipv4": [],
            "associated_ipv6": [],
            "verbose": "disabled" if not verbose else None
        }
        logger.debug(f"Invalid IP address: {ip}")
        logger.info(f"Processing {ip} (invalid) took {time.time() - start_time:.2f}s")
        return ip, result

    logger.info(f"Processing IP: {ip}")
    fqdns = reverse_dns_lookup(ip_obj, resolver)
    result = {
        "status": "success" if fqdns else "no_records",
        "fqdns": fqdns if fqdns else [],
        "associated_ipv4": [],
        "associated_ipv6": [],
        "verbose": "disabled" if not verbose else None
    }
    if not no_forward and fqdns:
        logger.info(f"Performing forward lookups for FQDNs of {ip}")
        associated_ipv4, associated_ipv6, verbose_data = get_associated_ips(fqdns, resolver, verbose)
        result["associated_ipv4"] = associated_ipv4
        result["associated_ipv6"] = associated_ipv6
        if verbose:
            result["verbose"] = verbose_data
    
    logger.info(f"Processing {ip} took {time.time() - start_time:.2f}s")
    logger.debug(f"Exiting process_ip for {ip} with result: {result}")
    return ip, result

def format_output(temp_file_path, output_format, header, overview, show_invalid=False, show_no_records=False):
    """Format the processed results into JSON or CSV output.

    Args:
        temp_file_path: Path to temporary file with results.
        output_format: "json" or "csv".
        header: CSV header column name (e.g., "IP").
        overview: Dict with summary stats.
        show_invalid: If True, include invalid IPs in output (default: False).
        show_no_records: If True, include no-records IPs in output (default: False).

    Returns:
        Formatted string output.
    """
    logger.debug("Entering format_output")
    start_time = time.time()
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat() + "Z"
    overview_section = {
        "summary": f"PTRack processed {overview['total_ips']} IPs in {round(overview['runtime'], 2)}s: {overview['processed_count']} successful, {overview['no_records_count']} no records, {overview['invalid_count']} skipped.",
        "file": str(overview["file"]),
        "total_ips": overview["total_ips"],
        "successful": overview["processed_count"],
        "no_records": overview["no_records_count"],
        "skipped": overview["invalid_count"],
        "dns_servers": overview["dns_servers"],
        "generated_at": timestamp,
        "runtime_seconds": round(overview["runtime"], 2)
    }

    result = {}
    with open(temp_file_path, 'r', encoding='utf-8') as temp_file:
        for line in temp_file:
            if line.strip():
                ip, data = json.loads(line.strip())
                if (show_invalid or data["status"] != "invalid") and (show_no_records or data["status"] != "no_records"):
                    result[ip] = data

    if output_format == "json":
        combined_output = {
            "overview": overview_section,
            "analysis": {header: result}
        }
        output = json.dumps(combined_output, indent=4, sort_keys=True)
    elif output_format == "csv":
        output = [
            f"# Overview",
            f"# {overview_section['summary']}",
            f"File: {overview['file']}",
            f"Total IPs: {overview['total_ips']}",
            f"Successful: {overview['successful']}",
            f"No Records: {overview['no_records']}",
            f"Skipped: {overview['skipped']}",
            f"DNS Servers: {';'.join(overview['dns_servers'])}",
            f"Generated At: {timestamp}",
            f"Runtime (seconds): {round(overview['runtime'], 2)}",
            "",  # Line break
            "IP,Status,FQDNs,IPv4,IPv6,Verbose"
        ]
        for ip, info in result.items():
            fqdns_str = ";".join(info["fqdns"]) if info["fqdns"] else ""
            ipv4_str = ";".join(info["associated_ipv4"]) if info["associated_ipv4"] else ""
            ipv6_str = ";".join(info["associated_ipv6"]) if info["associated_ipv6"] else ""
            verbose_str = json.dumps(info["verbose"]) if info.get("verbose") != "disabled" else "disabled"
            row = f"{ip},{info['status']},{fqdns_str},{ipv4_str},{ipv6_str},{verbose_str}"
            output.append(row)
        output = "\n".join(output)
    
    logger.info(f"Formatting output took {time.time() - start_time:.2f}s")
    logger.debug("Exiting format_output")
    return output

def load_cache(cache_file):
    """Load cached DNS results from a JSON file.

    Args:
        cache_file: Path to the cache file (optional).

    Returns:
        Dict of cached results, empty if no cache file or invalid.
    """
    logger.debug(f"Entering load_cache with {cache_file}")
    start_time = time.time()
    if cache_file:
        cache_path = Path(os.path.normpath(cache_file)).resolve()  # Normalize path for security
        if not str(cache_path).startswith(os.getcwd()):
            logger.error(f"Cache file path '{cache_file}' outside current directory")
            return {}
        if cache_path.exists():
            try:
                with cache_path.open('r', encoding='utf-8') as f:
                    cache = json.load(f)
                    logger.debug(f"Loaded cache: {cache}")
                    logger.info(f"Loading cache took {time.time() - start_time:.2f}s")
                    return cache
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache file '{cache_file}': {e}")
    logger.debug("Exiting load_cache with empty dict")
    logger.info(f"Loading cache (empty) took {time.time() - start_time:.2f}s")
    return {}

def save_cache(cache_file, temp_file_path, header):
    """Save DNS results to a cache file.

    Args:
        cache_file: Path to save the cache file (optional).
        temp_file_path: Path to temporary file with results.
        header: CSV header column name (e.g., "IP").
    """
    logger.debug(f"Entering save_cache with {cache_file}")
    start_time = time.time()
    if cache_file:
        cache_path = Path(os.path.normpath(cache_file)).resolve()  # Normalize path for security
        if not str(cache_path).startswith(os.getcwd()):
            logger.error(f"Cache file path '{cache_file}' outside current directory")
            return
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            result = {}
            with open(temp_file_path, 'r', encoding='utf-8') as temp_file:
                for line in temp_file:
                    if line.strip():
                        ip, data = json.loads(line.strip())
                        result[ip] = data
            with cache_path.open('w', encoding='utf-8') as f:
                json.dump({header: result}, f, indent=4)
            logger.debug(f"Saved cache to {cache_file}")
            logger.info(f"Saving cache took {time.time() - start_time:.2f}s")
        except (IOError, PermissionError) as e:
            logger.warning(f"Failed to save cache to '{cache_file}': {e}")
    else:
        logger.info(f"Cache saving skipped (no cache file specified), took {time.time() - start_time:.2f}s")

def validate_dns_server(ip):
    """Validate a DNS server IP address.

    Args:
        ip: String IP address to validate.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logger.error(f"Invalid DNS server IP: {ip}")
        return False

def main():
    """Main function to run PTRack."""
    help_description = """
    PTRack: A Reverse and Forward DNS Lookup Tool

    Analyzes IP addresses from a CSV file, finding domain names (reverse DNS) and related IPs (forward DNS).
    Works on Windows, Mac, and Linux, scales to 10,000+ IPs.

    Usage:
        python ptrack.py input.csv 8.8.8.8
        python ptrack.py input.csv 8.8.8.8 --log-level=info
        python ptrack.py input.csv 8.8.8.8 --format=csv --verbose-output --cache-file=cache.json

    Options:
        --log-level: debug, info, warning, error (case-insensitive; default: warning)
        --no-forward: Skip finding related IPs (faster)
        --format: json (default) or csv
        --threads: Number of tasks (default: 8, max: 16)
        --timeout: DNS query timeout in seconds (default: 5)
        --cache-file: Save results to file (e.g., cache.json)
        --verbose-output: Show extra DNS details
        --batch-size: IPs per batch (default: 2000)
        --max-runtime: Max runtime in seconds (default: 3600)
        --show-invalid: Include invalid IPs in output (default: False)
        --show-no-records: Include no-records IPs in output (default: False)
        --version: Show tool version and exit
    """

    log_level_map = {lvl.lower(): lvl for lvl in ["DEBUG", "INFO", "WARNING", "ERROR"]}
    parser = argparse.ArgumentParser(description=help_description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_file", help="Path to CSV file with IPs in first column.")
    parser.add_argument("dns_server", help="Primary DNS server IP (e.g., 8.8.8.8).")
    parser.add_argument("--fallback-dns", help="Comma-separated fallback DNS servers.")
    parser.add_argument("--log-level", choices=list(log_level_map.keys()), default="warning", help="Logging level.")
    parser.add_argument("--no-forward", action="store_true", help="Skip forward lookups.")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format.")
    parser.add_argument("--threads", type=int, default=8, help="Number of threads (default: 8, max: 16).")
    parser.add_argument("--timeout", type=float, default=5, help="DNS timeout in seconds (default: 5).")
    parser.add_argument("--cache-file", help="Path to cache file for speeding up runs.")
    parser.add_argument("--verbose-output", action="store_true", help="Include verbose DNS data.")
    parser.add_argument("--batch-size", type=int, default=2000, help="IPs per batch (default: 2000).")
    parser.add_argument("--max-runtime", type=float, default=3600, help="Max runtime in seconds (default: 3600).")
    parser.add_argument("--show-invalid", action="store_true", help="Include invalid IPs in output.")
    parser.add_argument("--show-no-records", action="store_true", help="Include no-records IPs in output.")
    parser.add_argument("--version", action="version", version=f"PTRack {__version__}", help="Show version and exit.")
    args = parser.parse_args()

    logger.setLevel(getattr(logging, log_level_map[args.log_level.lower()]))

    # Initialization timing
    init_start_time = time.time()

    # Sanitize and validate CSV file path
    csv_file = Path(os.path.normpath(args.csv_file)).resolve()
    if not str(csv_file).startswith(os.getcwd()):
        logger.error(f"CSV file path '{args.csv_file}' outside current directory")
        sys.exit(1)
    
    dns_servers = [args.dns_server]
    if args.fallback_dns:
        dns_servers.extend(args.fallback_dns.split(','))
    if not all(validate_dns_server(ip) for ip in dns_servers):
        sys.exit(1)
    args.threads = max(1, min(args.threads, 16))

    # Count total IPs with a size limit for security
    csv_read_start = time.time()
    with csv_file.open('r', newline='', encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        try:
            header_row = next(reader)
            if not header_row or not header_row[0].strip():
                raise ValueError("Empty or missing header")
        except StopIteration:
            logger.error("CSV file is empty.")
            sys.exit(1)
        total_ips = sum(1 for row in reader if row and row[0].strip())
        if total_ips > 1_000_000:  # Arbitrary limit for security
            logger.error(f"Input exceeds maximum allowed IPs (1,000,000): {total_ips}")
            sys.exit(1)
    logger.info(f"Reading CSV took {time.time() - csv_read_start:.2f}s")

    # Initial feedback with user-friendly details
    feedback = [
        "PTRack is starting up...",
        f"Task: Analyzing {total_ips} IPs from '{csv_file.name}'",
        f"DNS Servers: {', '.join(dns_servers)}",
        f"Output Format: {args.format.upper()}",
        f"Threads: {args.threads}, Batch Size: {args.batch_size}",
        f"Forward Lookups: {'Enabled' if not args.no_forward else 'Disabled'}",
        f"Verbose Output: {'Enabled' if args.verbose_output else 'Disabled'}",
        f"Cache File: '{args.cache_file}' (speeds up future runs)" if args.cache_file else "Cache: Disabled (use --cache-file to enable)",
        f"Show Invalid IPs: {'Enabled' if args.show_invalid else 'Disabled'}",
        f"Show No-Records IPs: {'Enabled' if args.show_no_records else 'Disabled'}",
        f"Max Runtime: {args.max_runtime} seconds",
        "Initializing... please wait."
    ]
    sys.stderr.write("\n".join(feedback) + "\n")
    sys.stderr.flush()
    time.sleep(2)  # Brief delay for ramp-up
    logger.info(f"Initialization took {time.time() - init_start_time:.2f}s")

    # Configure DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_servers
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout * 2

    # Load cache if specified
    cache_load_start = time.time()
    cache = load_cache(args.cache_file)
    header_key = next(iter(cache)) if cache else "IP"
    cached_data = cache.get(header_key, {})
    logger.info(f"Cache loading took {time.time() - cache_load_start:.2f}s")

    start_time = time.time()
    temp_file_path = None

    try:
        # Process IPs with streaming to temp file
        with csv_file.open('r', newline='', encoding='utf-8-sig') as f, tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as temp_file:
            temp_file_path = temp_file.name
            reader = csv.reader(f)
            header_row = next(reader)  # Skip header, already validated

            ip_rows = [(row[0].strip(), row) for row in reader if row and row[0].strip()]
            total_ips = len(ip_rows)
            processed_count = 0
            no_records_count = 0
            invalid_count = 0

            for batch_start in range(0, total_ips, args.batch_size):
                batch_start_time = time.time()
                if time.time() - start_time > args.max_runtime:
                    logger.error("Maximum runtime exceeded")
                    break
                batch_end = min(batch_start + args.batch_size, total_ips)
                batch_rows = ip_rows[batch_start:batch_end]

                with ThreadPoolExecutor(max_workers=args.threads) as executor:
                    futures = {executor.submit(process_ip, ip, resolver, cached_data, args.no_forward, args.verbose_output): ip for ip, _ in batch_rows}
                    for i, future in enumerate(futures, batch_start + 1):
                        try:
                            ip, result = future.result()
                            if result is not None:
                                temp_file.write(json.dumps([ip, result]) + '\n')
                                if result["status"] == "success":
                                    processed_count += 1
                                elif result["status"] == "no_records":
                                    no_records_count += 1
                                elif result["status"] == "invalid":
                                    invalid_count += 1
                            if i % max(1, total_ips // 100) == 0 or i == batch_end:
                                percentage = (i / total_ips) * 100
                                sys.stderr.write(f"\rProcessing IPs: {percentage:.0f}% ({i}/{total_ips})")
                                sys.stderr.flush()
                        except Exception as e:
                            logger.error(f"Error processing IP {ip}: {e}")
                temp_file.flush()
                logger.info(f"Batch {batch_start}-{batch_end} took {time.time() - batch_start_time:.2f}s")

            sys.stderr.write(f"\rProcessed {total_ips}/{total_ips} IPs{' '*20}\n")
            sys.stderr.flush()

        # Generate and output results
        runtime = time.time() - start_time
        overview = {
            "file": str(csv_file),
            "total_ips": total_ips,
            "processed_count": processed_count,
            "no_records_count": no_records_count,
            "invalid_count": invalid_count,
            "dns_servers": dns_servers,
            "runtime": runtime
        }
        output_start_time = time.time()
        output = format_output(temp_file_path, args.format, header_key, overview, args.show_invalid, args.show_no_records)
        print(output)
        logger.info(f"Output generation took {time.time() - output_start_time:.2f}s")
        
        # Handle caching
        save_cache_start = time.time()
        save_cache(args.cache_file, temp_file_path, header_key)
        logger.info(f"Cache handling completed in {time.time() - save_cache_start:.2f}s")
        logger.info(f"Processed {total_ips} IPs: {processed_count} successful, {no_records_count} no records, {invalid_count} skipped in {runtime:.2f}s")

    except FileNotFoundError:
        logger.error(f"CSV file '{csv_file}' not found.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error processing CSV file: {e}")
        sys.exit(1)
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

if __name__ == "__main__":
    main()