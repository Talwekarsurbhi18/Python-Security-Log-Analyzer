# Python Security Log Analyzer

A simple Python-based security log analyzer that identifies failed login attempts and flags potentially suspicious IP addresses based on repeated authentication failures.

## Features

* Analyzes security log files
* Detects failed and successful login attempts
* Extracts IP addresses using Regular Expressions
* Identifies IPs with repeated failed login attempts
* Generates a simple security analysis report

## Technologies Used

* Python
* Regular Expressions (Regex)
* File Handling
* Collections (`Counter`)

## Project Structure

```text
Python-Security-Log-Analyzer/
│
├── security_log_analyzer.py
├── security.log
├── report.txt
└── README.md
```

## How to Run

1. Clone the repository.
2. Open the project folder in Command Prompt or PowerShell.
3. Run:

```bash
py security_log_analyzer.py
```

4. The analysis results will be displayed in the terminal.
5. A `report.txt` file will be generated automatically.

## Detection Logic

The analyzer flags an IP address when it has **3 or more failed login attempts**.

> Note: Repeated failed login attempts are treated as potentially suspicious activity and do not by themselves confirm a security attack.

## Purpose

This project was created to practice Python automation and understand basic cybersecurity concepts such as authentication logs, failed login monitoring, IP analysis, and suspicious activity detection.
