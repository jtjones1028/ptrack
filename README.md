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

