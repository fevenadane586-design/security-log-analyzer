# Security Log Analyzer

A beginner-friendly Python cybersecurity project that analyzes authentication logs to identify suspicious login activity and potential brute-force attempts.

## Project Overview

Security teams review authentication logs to identify unusual login behavior that may indicate unauthorized access or credential attacks.

This project demonstrates a simple version of that process using Python. The program reads authentication events from a sample log file, analyzes failed and successful login activity, identifies suspicious patterns, displays findings in the terminal, and exports detected alerts to a CSV report.

## Features

- Reads authentication events from a CSV-formatted log file
- Counts successful and failed login attempts
- Tracks failed login attempts by source IP
- Identifies IP addresses exceeding a configurable failure threshold
- Detects successful logins that occur after repeated failures
- Assigns HIGH severity to suspicious authentication patterns
- Displays investigation results in the terminal
- Exports detected alerts to a CSV security report

## Detection Logic

The analyzer currently uses a threshold of **5 failed login attempts**.

### Possible Brute-Force Activity

If a source IP generates five or more failed authentication attempts, the program generates a high-severity alert.

### Successful Login After Repeated Failures

If the same source IP and account generate five or more failed attempts followed by a successful login, the program generates a separate high-severity alert.

This pattern may warrant further investigation because repeated authentication failures followed by success can indicate successful credential guessing. However, the detection alone does not prove that an account was compromised.

## Project Structure

```text
security-log-analyzer/
├── sample_logs/
│   └── authentication.log
├── log_analyzer.py
├── security_report.csv
├── README.md
├── .gitignore
└── LICENSE
```

## Sample Log Format

The project uses synthetic authentication data for demonstration purposes.

```text
timestamp,source_ip,username,status
2026-09-28 08:21:14,192.168.1.25,admin,failed
2026-09-28 08:21:19,192.168.1.25,admin,failed
2026-09-28 08:22:03,192.168.1.25,admin,success
```

No real user credentials or production security logs are included in this repository.

## How to Run

Python 3 is required.

Clone the repository:

```bash
git clone https://github.com/fevenadane586-design/security-log-analyzer.git
```

Move into the project directory:

```bash
cd security-log-analyzer
```

Run the analyzer:

```bash
python log_analyzer.py
```

The program will analyze the authentication log, display the findings in the terminal, and create:

```text
security_report.csv
```

## Example Findings

Using the included synthetic dataset, the analyzer processes:

- 20 authentication events
- 6 successful logins
- 14 failed logins

The test data produces detections including:

- Six failed attempts against the `admin` account followed by a successful login from `192.168.1.25`
- Five failed authentication attempts from `10.0.0.72`
- Source IPs exceeding the configured brute-force threshold

## Skills Demonstrated

- Python scripting
- Security log analysis
- Authentication-event analysis
- Basic brute-force detection
- CSV parsing and report generation
- Security alert logic
- Defensive cybersecurity concepts

## Limitations

This is an educational cybersecurity project rather than a production intrusion-detection system.

Current limitations include:

- Uses synthetic authentication data
- Uses a simple fixed threshold
- Does not currently use time-window-based detection
- Does not perform IP reputation or geolocation analysis
- Does not integrate with a SIEM or live authentication source
- Alerts require analyst investigation before determining whether activity is malicious

## Future Improvements

Possible improvements include:

- Time-based brute-force detection
- Configurable alert thresholds
- Additional severity levels
- Detection of attacks against multiple accounts
- Integration with Windows or Linux authentication logs
- SIEM integration
- Automated summary statistics and visualization

## Author

**Feben Adane**

Cybersecurity trainee interested in SOC operations, network security, log analysis, and threat detection.