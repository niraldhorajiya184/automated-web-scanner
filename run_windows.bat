@echo off
set /p TARGET=Enter website URL you are authorized to test (example https://example.com): 
py main.py "%TARGET%" --json report.json --csv findings.csv
if errorlevel 1 (
  echo.
  echo Scan finished with an error. Read the message above.
) else (
  echo.
  echo Done. Reports are in this folder.
)
pause
