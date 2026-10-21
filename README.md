# Automated Web Scanner

A beginner-friendly Python project that checks a website's HTTP security headers and looks for common CORS configuration mistakes. It prints a report and can save JSON and CSV output.

## Features
- Checks for HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Sends a harmless test `Origin` header to inspect CORS behavior.
- Sends an `OPTIONS` preflight-style request to inspect advertised CORS settings.
- Reports the HTTP status, final URL, evidence, severity, and remediation suggestions.
- Exports reports to JSON and CSV.
- Uses only Python's standard library: no `pip install` required.

## Requirements
- Python 3.10 or newer recommended.
- Internet access for scanning public sites.
- VS Code (optional).

## Run in VS Code
1. Extract the ZIP file.
2. Open the extracted `automated_web_scanner` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Check Python:
   - Windows: `py --version` (or `python --version`)
   - Linux/Kali: `python3 --version`
5. Run one of these commands:

   Windows:
   ```powershell
   py main.py https://silveroakuni.ac.in
   ```

   Linux / Kali:
   ```bash
   python3 main.py silveroakuni.ac.in
   ```

6. To save reports:

   Windows:
   ```powershell
   py main.py https://silveroakuni.ac.in --json report.json --csv findings.csv
   ```

   Linux / Kali:
   ```bash
   python3 main.py https://example.com --json report.json --csv findings.csv
   ```

7. You can also run `main.py` with the Run Python File button. If no URL is passed, it asks you to enter one.

## Try it safely
Start with `https://silveroakuni.ac.in` or a site you own / have written permission to assess. Only scan systems you are authorized to test. The scanner makes a GET request and an OPTIONS request; it does not attempt exploitation, brute force, or data extraction.

## Understanding the results
- **Missing security header**: the response did not include that header. Whether it is required depends on the site and its architecture.
- **CORS wildcard**: `Access-Control-Allow-Origin: *` allows any website to read eligible non-credentialed cross-origin responses. It is not automatically a vulnerability for public data.
- **Origin reflection**: if the server returns the supplied test origin, it may be accepting arbitrary origins. Confirm with the application's intended origin policy.
- **Severity**: an estimate for triage, not a guaranteed impact rating.
- **No finding** does not mean the site is secure. This is a lightweight screening tool, not a complete security audit.

## Project structure
```text
automated_web_scanner/
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
├── run_windows.bat
└── run_kali.sh
```

## Troubleshooting
- **`python` / `py` not found**: install Python 3.10+ and enable “Add Python to PATH” on Windows.
- **Timeout / DNS error**: check the URL and network connection; retry with `--timeout 20`.
- **SSL certificate error**: use a correctly configured HTTPS site. The scanner intentionally verifies TLS certificates and does not disable certificate validation.
- **HTTP 403 / 405**: the server may block automated requests or OPTIONS. The report may still contain useful header information.
- **No CORS headers**: this may be normal if the site does not support cross-origin browser requests.

## Academic project summary
**Objective:** Automate initial web security checks by identifying missing HTTP security headers and suspicious CORS behavior.

**Methodology:** Send a normal HTTP GET request, inspect response headers, send a test Origin, and issue an OPTIONS preflight-style request. Record evidence and recommendations in a terminal report and optional JSON/CSV files.

**Limitations:** Does not crawl pages, test authenticated endpoints, verify browser exploitability, or replace manual testing.
