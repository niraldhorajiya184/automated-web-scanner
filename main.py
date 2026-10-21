#!/usr/bin/env python3
"""
Automated Web Scanner
Audits HTTP security headers and common CORS misconfigurations.
Use only on websites you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import ssl

USER_AGENT = "AutomatedWebScanner/1.0 (authorized security audit)"
TEST_ORIGIN = "https://cors-audit.invalid"

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High", "Enforces HTTPS in supported browsers.",
        "Enable HSTS on HTTPS sites; choose max-age carefully."
    ),
    "Content-Security-Policy": (
        "High", "Helps reduce XSS and content-injection risk.",
        "Define a restrictive Content-Security-Policy suited to the application."
    ),
    "X-Content-Type-Options": (
        "Medium", "Prevents MIME-type sniffing.",
        "Set X-Content-Type-Options: nosniff."
    ),
    "X-Frame-Options": (
        "Medium", "Legacy clickjacking protection; CSP frame-ancestors is preferred.",
        "Set X-Frame-Options: DENY or SAMEORIGIN, or configure CSP frame-ancestors."
    ),
    "Referrer-Policy": (
        "Low", "Controls how much referrer information browsers send.",
        "Consider strict-origin-when-cross-origin or a stricter policy."
    ),
    "Permissions-Policy": (
        "Low", "Restricts browser features such as camera and microphone.",
        "Set a Permissions-Policy appropriate to the features the site needs."
    ),
}

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames/passwords are not supported.")
    return value

def request_url(url: str, method: str = "GET", extra_headers: dict[str, str] | None = None,
                timeout: float = 10.0) -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    req = Request(url, headers=headers, method=method)
    try:
        # Use the platform's normal TLS certificate validation.
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            return {
                "status": response.status,
                "headers": {k.lower(): v.strip() for k, v in response.headers.items()},
                "final_url": response.geturl(),
                "error": None,
            }
    except HTTPError as exc:
        return {
            "status": exc.code,
            "headers": {k.lower(): v.strip() for k, v in exc.headers.items()},
            "final_url": exc.geturl(),
            "error": None,
        }
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": None, "headers": {}, "final_url": url, "error": str(exc)}

def add_finding(findings: list[dict[str, str]], severity: str, title: str,
                evidence: str, recommendation: str) -> None:
    findings.append({
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    })

def scan(url: str, timeout: float = 10.0) -> dict[str, Any]:
    normalized = normalize_url(url)
    result = request_url(normalized, timeout=timeout)
    findings: list[dict[str, str]] = []
    if result["error"]:
        add_finding(findings, "Error", "Request failed", result["error"],
                    "Check the URL, network connection, DNS, and whether the site is reachable.")
        return {
            "scanner": "Automated Web Scanner", "version": "1.0",
            "target": normalized, "scanned_at": datetime.now(timezone.utc).isoformat(),
            "status_code": None, "final_url": normalized, "headers": {},
            "cors": {"tested": False, "note": "CORS checks skipped because the initial request failed."},
            "findings": findings,
        }

    headers = result["headers"]
    final_url = result["final_url"]
    is_https = urlparse(final_url).scheme == "https"

    for header, (severity, purpose, recommendation) in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if not value:
            if header == "Strict-Transport-Security" and not is_https:
                continue
            add_finding(findings, severity, f"Missing {header}",
                        f"{header} was not present in the response.",
                        recommendation)
        else:
            # Informational finding is avoided for present headers.
            pass

    if not is_https:
        add_finding(findings, "High", "Target did not finish on HTTPS",
                    f"Final URL scheme is {urlparse(final_url).scheme}.",
                    "Serve the site over HTTPS and redirect HTTP to HTTPS.")

    server = headers.get("server")
    if server:
        add_finding(findings, "Info", "Server header disclosed",
                    f"Server: {server}",
                    "Consider minimizing version/product details in the Server response header.")

    cors_headers = {}
    cors_notes: list[str] = []
    cors_get = request_url(normalized, extra_headers={"Origin": TEST_ORIGIN}, timeout=timeout)
    if cors_get["error"]:
        cors_notes.append("GET request with test Origin failed: " + cors_get["error"])
    else:
        h = cors_get["headers"]
        cors_headers = {
            "access-control-allow-origin": h.get("access-control-allow-origin"),
            "access-control-allow-credentials": h.get("access-control-allow-credentials"),
            "vary": h.get("vary"),
        }
        allow_origin = (h.get("access-control-allow-origin") or "").strip()
        allow_credentials = (h.get("access-control-allow-credentials") or "").strip().lower()
        if allow_origin == "*":
            severity = "Medium"
            evidence = "The response allows Access-Control-Allow-Origin: *."
            if allow_credentials == "true":
                severity = "High"
                evidence += " Access-Control-Allow-Credentials is also true; browsers do not permit wildcard origin with credentialed CORS, but this combination indicates a potentially unsafe policy."
            add_finding(findings, severity, "CORS wildcard origin",
                        evidence,
                        "Allow only trusted origins when cross-origin access is required. Do not use wildcard origins for sensitive APIs.")
        elif allow_origin == TEST_ORIGIN:
            severity = "High" if allow_credentials == "true" else "Medium"
            add_finding(findings, severity, "CORS reflects the supplied test Origin",
                        f"The response returned Access-Control-Allow-Origin: {allow_origin} for an untrusted test origin."
                        + (" Credentials are also allowed." if allow_credentials == "true" else ""),
                        "Use an explicit allowlist of trusted origins; never reflect arbitrary Origin values.")
        elif allow_origin:
            cors_notes.append(f"Server returned Access-Control-Allow-Origin: {allow_origin}")
        else:
            cors_notes.append("No Access-Control-Allow-Origin header was returned for the test Origin.")

    # A non-destructive OPTIONS request checks advertised preflight policy.
    options = request_url(normalized, method="OPTIONS", extra_headers={
        "Origin": TEST_ORIGIN,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization, content-type",
    }, timeout=timeout)
    if options["error"]:
        cors_notes.append("OPTIONS preflight request failed: " + options["error"])
    else:
        oh = options["headers"]
        for name in ("access-control-allow-origin", "access-control-allow-methods",
                     "access-control-allow-headers", "access-control-allow-credentials", "vary"):
            if oh.get(name):
                cors_headers["options_" + name] = oh[name]
        options_origin = (oh.get("access-control-allow-origin") or "").strip()
        options_credentials = (oh.get("access-control-allow-credentials") or "").strip().lower()
        if options_origin == TEST_ORIGIN:
            add_finding(findings, "High" if options_credentials == "true" else "Medium",
                        "CORS preflight accepts the test Origin",
                        f"OPTIONS returned Access-Control-Allow-Origin: {options_origin}."
                        + (" Credentials are also allowed." if options_credentials == "true" else ""),
                        "Verify the origin against a strict allowlist and restrict methods/headers to those required.")
        elif options_origin == "*":
            add_finding(findings, "Medium", "CORS preflight uses wildcard origin",
                        "OPTIONS returned Access-Control-Allow-Origin: *.",
                        "Use an explicit origin allowlist for APIs containing non-public data.")

    return {
        "scanner": "Automated Web Scanner",
        "version": "1.0",
        "target": normalized,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "status_code": result["status"],
        "final_url": final_url,
        "headers": headers,
        "cors": {"tested": True, "test_origin": TEST_ORIGIN, "observed_headers": cors_headers,
                 "notes": cors_notes},
        "findings": findings,
    }

def print_report(report: dict[str, Any]) -> None:
    print("\n" + "=" * 68)
    print("AUTOMATED WEB SCANNER — SECURITY AUDIT REPORT")
    print("=" * 68)
    print(f"Target:      {report['target']}")
    print(f"Final URL:   {report['final_url']}")
    print(f"HTTP status: {report['status_code'] if report['status_code'] is not None else 'Request failed'}")
    print(f"Scanned at:  {report['scanned_at']}")
    print("-" * 68)
    findings = report["findings"]
    if not findings:
        print("No missing-header or CORS findings were identified by these checks.")
    else:
        for i, item in enumerate(findings, 1):
            print(f"\n{i}. [{item['severity'].upper()}] {item['title']}")
            print(f"   Evidence: {item['evidence']}")
            print(f"   Fix:      {item['recommendation']}")
    print("\nCORS notes:")
    for note in report.get("cors", {}).get("notes", []):
        print(f" - {note}")
    print("\nNote: This is a lightweight screening tool, not a full penetration test.")
    print("Confirm findings manually; behavior may vary by endpoint, browser, and authentication.")
    print("=" * 68 + "\n")

def save_json(report: dict[str, Any], path: str) -> None:
    Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

def save_csv(report: dict[str, Any], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["severity", "title", "evidence", "recommendation"])
        writer.writeheader()
        writer.writerows(report["findings"])

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a website's security headers and common CORS configuration issues."
    )
    parser.add_argument("url", nargs="?", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_path", help="Save full report as JSON")
    parser.add_argument("--csv", dest="csv_path", help="Save findings as CSV")
    args = parser.parse_args()

    url = args.url
    if not url:
        try:
            url = input("Enter a website URL you are authorized to test: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 130
    try:
        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")
        report = scan(url, timeout=args.timeout)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    print_report(report)
    try:
        if args.json_path:
            save_json(report, args.json_path)
            print(f"JSON report saved: {args.json_path}")
        if args.csv_path:
            save_csv(report, args.csv_path)
            print(f"CSV findings saved: {args.csv_path}")
    except OSError as exc:
        print(f"Could not save report: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
