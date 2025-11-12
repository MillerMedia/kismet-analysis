# Bluetooth Warwalking Analysis Tool

A Python tool for analyzing Kismet Bluetooth capture files to extract insights from warwalking data.

## Overview

This tool processes Kismet database files (`.kismet`) and provides comprehensive analysis of Bluetooth devices discovered during warwalking sessions. It can analyze single files or batch process entire directories, aggregating statistics across multiple capture files.

## Features

- **Comprehensive Device Analysis**: Analyzes BTLE and BR/EDR devices with detailed statistics
- **Batch Processing**: Process multiple `.kismet` files in a folder and aggregate results
- **Device Tracking**: Identifies named devices, manufacturers, service UUIDs, and trackable devices
- **Signal Analysis**: Signal strength distribution, range estimation, and path loss analysis
- **Temporal Analysis**: Device discovery patterns, persistence tracking, and time-based statistics
- **Privacy Metrics**: Security and privacy analysis including trackable vs anonymous devices
- **Geographic Data**: GPS coverage analysis when location data is available

## Requirements

- Python 3.6+
- sqlite3 (included with Python)
- Optional: `netaddr` for MAC address manufacturer lookup
  ```bash
  pip install netaddr
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/MillerMedia/kismet-analysis.git
   cd kismet-analysis
   ```

2. (Optional) Install netaddr for enhanced manufacturer identification:
   ```bash
   pip install netaddr
   ```

## Usage

### Single File Analysis

Analyze a single Kismet database file:

```bash
python3 index.py path/to/file.kismet
```

### Batch Processing

Process all `.kismet` files in a directory:

```bash
python3 index.py /path/to/folder
```

The tool will:
- Find all `.kismet` files in the specified directory
- Process each file
- Aggregate statistics across all files
- Display a combined analysis report

## Output

The tool provides detailed analysis including:

- Total device counts by type
- Bluetooth device breakdown (BTLE vs BR/EDR)
- Named vs anonymous devices
- Manufacturer identification
- Signal strength statistics and distribution
- GPS/location coverage (when available)
- Device discovery patterns over time
- Device persistence analysis
- Service UUID analysis
- Security and privacy metrics
- Packet statistics
- Device density calculations

## Example

```bash
$ python3 index.py ./kismet-data/
Found 3 kismet file(s) in ./kismet-data/
Processing files and aggregating results...

Processing: capture-2024-01-15.kismet...
Processing: capture-2024-01-16.kismet...
Processing: capture-2024-01-17.kismet...

============================================================
KISMET BLUETOOTH WARWALKING SUMMARY
============================================================
...
```

## License

This project is open source and available for use in security research and educational purposes.

## Support

If you find this tool useful for your research or conference presentation, consider supporting its development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/millermedia)

---

*Created for security research and warwalking analysis. Use responsibly and ethically.*

