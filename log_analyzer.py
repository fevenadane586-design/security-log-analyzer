import csv
from collections import Counter, defaultdict

# File containing authentication events
LOG_FILE = "sample_logs/authentication.log"

# Number of failed attempts that will trigger an alert
BRUTE_FORCE_THRESHOLD = 5
OUTPUT_FILE = "security_report.csv"

def read_logs(filename):
    """Read authentication events from a CSV-formatted log file."""
    events = []

    try:
        with open(filename, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                events.append(row)

    except FileNotFoundError:
        print(f"[ERROR] Could not find: {filename}")

    return events


def analyze_logs(events):
    """Analyze login events for suspicious authentication activity."""

    failed_by_ip = Counter()
    failed_by_user = Counter()
    failures_before_success = defaultdict(int)
    alerts = []

    total_success = 0
    total_failed = 0

    for event in events:
        ip = event["source_ip"]
        username = event["username"]
        status = event["status"].lower()

        if status == "failed":
            total_failed += 1
            failed_by_ip[ip] += 1
            failed_by_user[username] += 1
            failures_before_success[(ip, username)] += 1

        elif status == "success":
            total_success += 1

            previous_failures = failures_before_success[(ip, username)]

            if previous_failures >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "severity": "HIGH",
                    "type": "Successful login after repeated failures",
                    "source_ip": ip,
                    "username": username,
                    "attempts": previous_failures
                })

            failures_before_success[(ip, username)] = 0

    for ip, attempts in failed_by_ip.items():
        if attempts >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "type": "Possible brute-force activity",
                "source_ip": ip,
                "username": "Multiple/Unknown",
                "attempts": attempts
            })

    return {
        "total_events": len(events),
        "successful_logins": total_success,
        "failed_logins": total_failed,
        "failed_by_ip": failed_by_ip,
        "failed_by_user": failed_by_user,
        "alerts": alerts
    }


def display_report(results):
    """Display the security analysis in the terminal."""

    print("\n" + "=" * 50)
    print("SECURITY LOG ANALYSIS REPORT")
    print("=" * 50)

    print(f"Total Events:      {results['total_events']}")
    print(f"Successful Logins: {results['successful_logins']}")
    print(f"Failed Logins:     {results['failed_logins']}")

    print("\nTOP SOURCES OF FAILED LOGINS")
    print("-" * 50)

    for ip, count in results["failed_by_ip"].most_common(5):
        print(f"{ip:<20} {count} failed attempts")

    print("\nSECURITY ALERTS")
    print("-" * 50)

    if not results["alerts"]:
        print("No high-severity authentication alerts detected.")
    else:
        for alert in results["alerts"]:
            print(
                f"[{alert['severity']}] {alert['type']}\n"
                f"Source IP: {alert['source_ip']}\n"
                f"Account: {alert['username']}\n"
                f"Failed Attempts: {alert['attempts']}\n"
            )
def display_report(results):
    # existing code above
    ...


def export_report(results, filename):
    """Export detected security alerts to a CSV report."""

    with open(filename, "w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "severity",
            "alert_type",
            "source_ip",
            "username",
            "failed_attempts"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for alert in results["alerts"]:
            writer.writerow({
                "severity": alert["severity"],
                "alert_type": alert["type"],
                "source_ip": alert["source_ip"],
                "username": alert["username"],
                "failed_attempts": alert["attempts"]
            })

    print(f"\nSecurity report exported to: {filename}")



def main():
    print("Loading authentication logs...")

    events = read_logs(LOG_FILE)

    if not events:
        print("No log events available for analysis.")
        return

    results = analyze_logs(events)
    display_report(results)
    export_report(results, OUTPUT_FILE)


if __name__ == "__main__":
    main()
