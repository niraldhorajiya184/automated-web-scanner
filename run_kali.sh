#!/usr/bin/env bash
set -e
read -r -p "Enter website URL you are authorized to test (example https://example.com): " TARGET
python3 main.py "$TARGET" --json report.json --csv findings.csv
