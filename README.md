# PortScanner

A lightweight, multi-threaded TCP port scanner with a Windows Forms GUI. Built with C# and .NET 10.0.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![.NET](https://img.shields.io/badge/.NET-10.0-purple)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Flexible targeting** — scan a single IP, hostname, or an entire CIDR subnet (e.g. `192.168.1.0/24`)
- **Port presets** — quickly select common port groups (Top 20, Web, Database, Mail) or define custom ranges
- **Async multi-threaded scanning** — configurable thread count and per-port timeout for fast, controlled scans
- **Banner grabbing** — optionally probe open ports to capture service banners (HTTP, SSH, SMTP, etc.)
- **Service identification** — automatically labels ~50 well-known ports (SSH, HTTP, RDP, MySQL, etc.)
- **Real-time results** — live-updating ListView, progress bar, and a timestamped log tab
- **CSV export** — save scan results to a `.csv` file for further analysis

## Requirements

- **OS:** Windows 10/11 (Windows Forms dependency)
- **.NET 10.0 SDK** — [download here](https://dotnet.microsoft.com/download/dotnet/10.0)

## Getting Started

### Clone the repo

```bash
git clone https://github.com/laredding2/PortScanner.git
cd PortScanner
```

### Build and run

```bash
dotnet build
dotnet run
```

### Publish a standalone executable

```bash
# Framework-dependent (smaller, requires .NET runtime on target machine)
dotnet publish -c Release

# Self-contained single-file (no runtime needed)
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

The compiled binary will be in `bin/Release/net10.0-windows/publish/`.

## Usage

1. **Enter a target** in the top field:
   - Single host: `192.168.1.1` or `myserver.local`
   - Subnet: `192.168.1.0/24` (max /22, or 1022 hosts)

2. **Select ports** using a preset dropdown or enter a custom range / comma-separated list:
   - Range: `1` to `1024`
   - List: `22,80,443,3306,8080`

3. **Configure options:**
   - **Timeout (ms):** how long to wait per port before marking it closed (default `200`)
   - **Max Threads:** concurrency limit (default `100`)
   - **Grab Banners:** toggle to probe open ports for response data
   - **Resolve Hostnames:** reverse-DNS lookup for scanned IPs

4. **Start Scan** and watch results populate in real time. Open ports appear highlighted in the list view.

5. **Export** results to CSV with the Export button, or review the timestamped log in the **Log** tab.

## Port Presets

| Preset | Ports |
|---|---|
| Common (Top 20) | 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080 |
| Web Ports | 80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000 |
| Database Ports | 1433, 1521, 3306, 5432, 6379, 9042, 27017, 28015 |
| Mail Ports | 25, 110, 143, 465, 587, 993, 995 |
| Full Range | 1–1024 or 1–65535 |

## Project Structure

```
PortScanner/
├── PortScanner.cs        # Application source (Form, scanner logic, UI)
├── PortScanner.csproj    # Project file (.NET 10.0, WinExe output)
└── README.md
```

## Legal Disclaimer

**Only scan networks and systems that you own or have explicit written permission to scan.** Unauthorized port scanning may violate local, state, or federal laws depending on your jurisdiction. This tool is intended for legitimate network administration, security auditing, and educational purposes. The author assumes no liability for misuse.

## License

This project is licensed under the [MIT License](LICENSE).
