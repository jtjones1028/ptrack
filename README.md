# PTRack: Reverse and Forward DNS Lookup Tool

**PTRack** is a fast, scalable Python tool for performing reverse DNS (PTR) lookups and optional forward (A/AAAA) lookups on IP addresses listed in a CSV file. It outputs results in JSON or CSV format, optimized with threading, caching, and customizable output options—perfect for network analysis on Windows, Mac, and Linux.

## Features
- **Input**: Processes CSV files with IPs in the first column (header required, e.g., "IP").
- **DNS Lookups**: Performs reverse (PTR) and optional forward (A/AAAA) lookups using a specified DNS server.
- **Output**: Generates structured JSON (default) or CSV with an overview and detailed analysis, customizable via `--show-invalid` and `--show-no-records`.
- **Cross-Platform**: Runs seamlessly on Windows, Mac, and Linux without modification.
- **Progress**: Displays real-time plain text updates to `stderr` (e.g., "Processing IPs: 50% (2500/5000)").
- **Encoding**: Ensures consistent UTF-8 handling for all I/O.
- **Logging**: Offers configurable levels (`debug`, `info`, `warning`, `error`) with performance metrics.
- **Security**: Includes input validation, path sanitization, and a 1M IP limit to prevent abuse.
- **Speed**: Leverages threading (default: 8, max: 16) and optional caching via `--cache-file` for efficiency.
- **Scalability**: Handles 10,000+ IPs with batching (default: 2000 IPs per batch).

## Installation

### Prerequisites
- **Python 3.9+**: Required for compatibility with `dnspython`.
- **Poetry**: Package manager for easy dependency management and installation.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/jtjones1028/ptrack.git
   cd ptrack

2. **Install with Poetry**:
   ```bash
   poetry install

3. **Verify Installation**:
   ```bash
   poetry run ptrack --version

## How to Use the Tool

**PTRack** is a command-line tool designed for simplicity and flexibility. Here’s a step-by-step guide to using it effectively:

1. **Prepare Your CSV File**:
   - Create a CSV with a header (e.g., "IP") in the first column, followed by IP addresses (e.g., `8.8.8.8`, `192.168.0.1`).
   - Example (`ips.csv`):
     ```
     IP
     8.8.8.8
     192.168.0.1
     invalid_ip
     ```

2. **Run the Tool**:
   - Basic command:
     ```bash
     poetry run ptrack ips.csv 8.8.8.8
     ```
   - Add options for customization (see **Common Options** below).

3. **Interpret the Output**:
   - **JSON (default)**: Check `"overview"` for stats and `"analysis"` for successful lookups (configurable with `--show-invalid` and `--show-no-records`).
   - **CSV**: Open in a spreadsheet for tabular data with comments summarizing stats.

4. **Leverage Caching**:
   - Use `--cache-file=cache.json` to save results and speed up future runs on the same IPs.

5. **Monitor Progress**:
   - Watch `stderr` for updates (e.g., `"Processing IPs: 50% (2500/5000)"`).
   - Enable `--log-level=info` for detailed timing and cache usage logs.

## Common Options

- **Detailed Logs**: `--log-level=info` (e.g., `[INFO] Processing 8.8.8.8 took 0.45s`).
- **CSV Output**: `--format=csv` (spreadsheet-friendly).
- **Cache Results**: `--cache-file=cache.json` (reduces runtime on repeat runs).
- **Show All IPs**: `--show-invalid` (includes invalid IPs), `--show-no-records` (includes IPs with no DNS records).
- **Version Check**: `--version` (displays `PTRack 1.0.0`).

## Common Use Cases

**PTRack** is versatile for various network-related tasks. Here are some typical scenarios and how to apply the tool:

### 1. Checking Public IP DNS Records
- **Scenario**: You have a list of public IPs (e.g., from a server log) and want to identify their domains.
- **Command**:
  ```bash
  poetry run ptrack public_ips.csv 8.8.8.8