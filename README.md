# Network Security Scanner

> Python-based local network scanner using Nmap. Discovers active hosts,
> identifies open ports and services, evaluates risk levels, and generates
> a visual HTML report with interactive charts.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Nmap](https://img.shields.io/badge/Nmap-7.94-green?logo=linux)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Project Overview

This tool performs a full SYN scan of a local network subnet, detects
operating systems and service versions, and classifies each open port
by risk level (critical / high / medium / low). Results are rendered
as a self-contained HTML report with Chart.js visualizations.

**Key objectives:**
- Map all active devices on a local network
- Identify exposed services and evaluate their risk
- Practice real threat intelligence interpretation with Shodan
- Build automated security reporting with Python + Jinja2

---

## Architecture

Nmap SYN Scan → python-nmap → Risk classification → Jinja2 template → HTML Report

**Stack:**
- **Nmap** — network discovery and port scanning engine
- **python-nmap** — Python wrapper for Nmap output parsing
- **Jinja2** — HTML report templating
- **Chart.js** — interactive risk distribution charts

---

## Sample Report

A sample report with anonymized IPs is available here:
[docs/sample-report.html](docs/sample-report.html)

> ⚠️ IP addresses and hostnames in screenshots have been anonymized
> to protect network privacy.

---

## Results (real scan — home lab network)

| Metric                  | Value          |
|-------------------------|----------------|
| Active hosts discovered | 8		   |
| Critical risk hosts     | 1 		   |
| Medium risk hosts       | 4  		   |
| Low risk hosts          | 3 		   |
| Total open ports found  | 19             |
| Most exposed service    | SMB (port 445) |
| Scan duration           | ~8 minutes     |

---

## Screenshots

### HTML report — risk overview
![Report overview](docs/screenshots/report-overview.png)

### Risk distribution and top services charts
![Charts](docs/screenshots/report-charts.png)

### Critical host detected — Windows with SMB exposed
![Critical host](docs/screenshots/report-critical.png)

---

## Usage

### Prerequisites
- Python 3.10+
- Nmap installed (`sudo apt install nmap`)
- Run as root (required for SYN scan)

### Setup

```bash
git clone https://github.com/pacojuliancuesta/network-scanner
cd network-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure your network range

Edit `scripts/scanner.py` line 7:
```python
NETWORK = "192.168.1.0/24"  # Change to your subnet
```

### Run

```bash
sudo venv/bin/python scripts/scanner.py
```

The HTML report is saved to `reports/scan_YYYYMMDD_HHMMSS.html`.

---

## Risk Classification

| Level    | Color | Examples                         |
|----------|-------|----------------------------------|
| Critical | 🔴    | SMB 445, RDP 3389, MongoDB 27017 |
| High     | 🟠    | FTP 21, MySQL 3306, RPC 135      |
| Medium   | 🟡    | SSH 22, HTTP 80, SMTP 25         |
| Low      | 🟢    | HTTPS 443, DNS 53                |

---

## Key Learnings

- A Windows machine with SMB (445), RPC (135) and NetBIOS (139) open
  is the exact attack surface exploited by EternalBlue / WannaCry
- IoT devices (Smart TVs) expose HTTP interfaces with no authentication
- First scan results arrived within seconds of starting — automated
  tools make network mapping trivial for an attacker on the same network
- OS detection via Nmap TCP/IP fingerprinting is surprisingly accurate
  even without sending intrusive probes

---

## License

MIT License — feel free to use and adapt this project.
