Web Recon + Misconfiguration Scanner (Flask)

A Flask-based web application that performs deeper recon and vulnerability checks using both lightweight and heavy scanning tools.

Features:
Nmap integration – Port scanning & service detection
Nikto integration – Web server misconfiguration checks
Subdomain enumeration – Identify subdomains via DNS brute force
Security headers analysis
Robots.txt inspection
Directory listing detection
JSON-based results + AI-ready structure for future enhancement

Why a separate Flask app?
System-level tools (Nmap, Nikto, subdomain enum) cannot run inside a browser.
Flask app leverages Python subprocesses to call these tools safely.
Designed for developers/security researchers who need deeper, slower, more detailed scans.

Tech Stack
Python (Flask, subprocess, requests)
Nmap, Nikto CLI tools
HTML (Jinja2 templates for UI
