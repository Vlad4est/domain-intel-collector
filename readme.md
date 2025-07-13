# OSINT Domain Scanner

A simple Python tool that collects information about domains using open-source intelligence techniques.

## What it does

This tool gathers:
- WHOIS information (who owns the domain)
- DNS records
- Website details
- Security reputation (using VirusTotal)

## Setup

1. Clone the repository:
```
git clone https://github.com/Vlad4est/osint-domain-scanner.git
cd osint-domain-scanner
```

2. Install requirements:
```
pip install python-whois dnspython requests beautifulsoup4
```

3. (Optional) Get a free VirusTotal API key at https://www.virustotal.com/gui/join-us

## How to use it

Basic usage:
```
python osint_collector.py example.com
```

With VirusTotal:
```
python osint_collector.py example.com --api-key YOUR_VIRUSTOTAL_API_KEY
```

## Example output

```
OSINT SUMMARY FOR: google.com
============================================================
IP Address: 142.250.190.78

--- WHOIS Information ---
Registrar: MarkMonitor, Inc.
Creation Date: 1997-09-15

--- DNS Information ---
A Records: 142.250.190.78
MX Records: alt1.aspmx.l.google.com.

--- Website Information ---
Title: Google
Server: gws
Technologies: Google Analytics

--- VirusTotal Information ---
Reputation: 609
Malicious: 0
Suspicious: 0
Harmless: 66
```

Results are saved in the `osint_results` folder as JSON files.

## Note

This tool is for educational purposes and to demonstrate Python skills for my internship application.