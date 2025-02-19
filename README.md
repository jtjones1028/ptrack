# PTRack: Reverse and Forward DNS Lookup Tool

**PTRack** analyzes IP addresses from a CSV file, performing reverse DNS (PTR) lookups and optional forward (A/AAAA) lookups. It’s designed for speed, scalability, and ease of use across Windows, Mac, and Linux, with features like threading, caching, and customizable output.

## Features
- **Input**: CSV with IPs in the first column (header required).
- **DNS Lookups**: Reverse (PTR) and forward (A/AAAA) lookups.
- **Output**: JSON (default) or CSV, with overview stats and detailed analysis.
- **Cross-Platform**: Works consistently on Windows, Mac, Linux.
- **Progress**: Real-time plain text updates to `stderr`.
- **Encoding**: UTF-8 throughout for consistency.
- **Logging**: Configurable levels (`debug`, `info`, `warning`, `error`) with performance metrics.
- **Security**: Path sanitization, input validation, resource limits.
- **Speed**: Threading (default: 8, max: 16) and optional caching.
- **Scalability**: Handles 10,000+ IPs efficiently with batching (default: 2000).

## Installation

### Prerequisites
- Python 3.6+
- Poetry (package manager)

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/ptrack.git
   cd ptrack