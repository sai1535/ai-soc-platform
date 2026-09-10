import json
from collections import Counter

INPUT_FILE = "../data/security_events.json"


def load_events():
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_event_counts(events):
    return Counter(
        event.get("event_id")
        for event in events
    )


# ---------------------------------------------------------
# 4625 - Failed Login Detection
# ---------------------------------------------------------

def detect_failed_logins(events):
    return [
        event
        for event in events
        if event.get("event_id") == 4625
    ]


def analyze_failed_users(failed_logins):
    user_failures = Counter()

    for event in failed_logins:
        event_data = event.get("event_data", {})

        username = (
            event_data.get("TargetUserName")
            or event_data.get("AccountName")
            or "Unknown"
        )

        user_failures[username] += 1

    return user_failures


def analyze_failed_ips(failed_logins):
    ip_failures = Counter()

    for event in failed_logins:
        event_data = event.get("event_data", {})

        ip_address = (
            event_data.get("IpAddress")
            or "Unknown"
        )

        ip_failures[ip_address] += 1

    return ip_failures


# ---------------------------------------------------------
# Brute Force Detection
# ---------------------------------------------------------

def detect_brute_force(failed_logins):
    alerts = []

    user_failures = analyze_failed_users(failed_logins)
    ip_failures = analyze_failed_ips(failed_logins)

    for username, count in user_failures.items():

        if count >= 10:
            alerts.append({
                "type": "Brute Force",
                "severity": "CRITICAL",
                "risk_score": 90,
                "target": username,
                "count": count,
                "message": (
                    f"Possible brute-force attack against "
                    f"user {username}: {count} failed login attempts."
                )
            })

        elif count >= 5:
            alerts.append({
                "type": "Suspicious Login Activity",
                "severity": "HIGH",
                "risk_score": 70,
                "target": username,
                "count": count,
                "message": (
                    f"Multiple failed login attempts against "
                    f"user {username}: {count} attempts."
                )
            })

    for ip_address, count in ip_failures.items():

        if ip_address != "Unknown" and count >= 5:
            alerts.append({
                "type": "Suspicious Source IP",
                "severity": "HIGH",
                "risk_score": 70,
                "target": ip_address,
                "count": count,
                "message": (
                    f"Multiple failed login attempts from "
                    f"IP address {ip_address}: {count} attempts."
                )
            })

    return alerts


# ---------------------------------------------------------
# 4688 - Process Creation
# ---------------------------------------------------------

def detect_process_creation(events):

    return [
        event
        for event in events
        if event.get("event_id") == 4688
    ]


# ---------------------------------------------------------
# 7045 - Windows Service Installation
# ---------------------------------------------------------

def detect_new_services(events):

    return [
        event
        for event in events
        if event.get("event_id") == 7045
    ]


# ---------------------------------------------------------
# 1102 - Security Log Cleared
# ---------------------------------------------------------

def detect_log_cleared(events):

    return [
        event
        for event in events
        if event.get("event_id") == 1102
    ]


# ---------------------------------------------------------
# Generate Security Alerts
# ---------------------------------------------------------

def generate_security_alerts(events):

    alerts = []

    failed_logins = detect_failed_logins(events)

    # Brute-force alerts
    alerts.extend(
        detect_brute_force(failed_logins)
    )

    # Process creation
    processes = detect_process_creation(events)

    if processes:
        alerts.append({
            "type": "Process Creation",
            "severity": "MEDIUM",
            "risk_score": 40,
            "target": "Windows Process",
            "count": len(processes),
            "message": (
                f"{len(processes)} process creation "
                f"events detected."
            )
        })

    # New Windows services
    services = detect_new_services(events)

    if services:
        alerts.append({
            "type": "New Windows Service",
            "severity": "HIGH",
            "risk_score": 75,
            "target": "Windows Service",
            "count": len(services),
            "message": (
                f"{len(services)} new Windows service "
                f"installation events detected."
            )
        })

    # Security log cleared
    logs_cleared = detect_log_cleared(events)

    if logs_cleared:
        alerts.append({
            "type": "Security Log Cleared",
            "severity": "CRITICAL",
            "risk_score": 100,
            "target": "Windows Security Log",
            "count": len(logs_cleared),
            "message": (
                "Windows Security audit log was cleared. "
                "Immediate investigation recommended."
            )
        })

    return alerts


# ---------------------------------------------------------
# Print Alerts
# ---------------------------------------------------------

def print_alerts(alerts):

    if not alerts:
        print("\nSecurity Alerts:")
        print("No suspicious activity detected.")
        return

    print("\nSecurity Alerts:")

    for number, alert in enumerate(alerts, start=1):

        print("\n------------------------------")
        print(f"Alert #{number}")

        print(f"Threat: {alert['type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Risk Score: {alert['risk_score']}/100")
        print(f"Target: {alert['target']}")
        print(f"Occurrences: {alert['count']}")

        print(
            f"Message: {alert['message']}"
        )

        print(
            "Recommended Action: Investigate"
        )


# ---------------------------------------------------------
# Main Analysis
# ---------------------------------------------------------

def analyze_events(events):

    print("=" * 60)
    print("AI-Assisted SOC - Detection Engine V3")
    print("=" * 60)

    print(
        f"\nTotal events analyzed: {len(events)}"
    )

    # Event summary
    event_counts = get_event_counts(events)

    print("\nEvent Summary:")

    for event_id, count in sorted(event_counts.items()):

        if event_id == 4624:
            print(
                f"4624 - Successful Logon: {count}"
            )

        elif event_id == 4625:
            print(
                f"4625 - Failed Logon: {count}"
            )

        elif event_id == 4688:
            print(
                f"4688 - Process Creation: {count}"
            )

        elif event_id == 7045:
            print(
                f"7045 - New Service: {count}"
            )

        elif event_id == 1102:
            print(
                f"1102 - Security Log Cleared: {count}"
            )

        else:
            print(
                f"{event_id}: {count}"
            )

    # Authentication analysis
    failed_logins = detect_failed_logins(events)

    print("\nAuthentication Analysis:")

    if not failed_logins:

        print("STATUS: NORMAL")
        print(
            "No failed logon events detected."
        )

    else:

        print(
            f"Failed login attempts detected: "
            f"{len(failed_logins)}"
        )

        user_failures = analyze_failed_users(
            failed_logins
        )

        print("\nFailed Logins by User:")

        for username, count in user_failures.items():

            print(
                f"{username}: "
                f"{count} failed attempts"
            )

        ip_failures = analyze_failed_ips(
            failed_logins
        )

        print("\nFailed Logins by IP:")

        for ip_address, count in ip_failures.items():

            print(
                f"{ip_address}: "
                f"{count} failed attempts"
            )

    # Generate alerts
    alerts = generate_security_alerts(events)

    print_alerts(alerts)

    # Final risk
    print("\nFinal Security Assessment:")

    if not alerts:

        print("Risk Score: 0/100")
        print("STATUS: NORMAL")
        print(
            "No suspicious activity detected."
        )

    else:

        highest_risk = max(
            alert["risk_score"]
            for alert in alerts
        )

        print(
            f"Highest Risk Score: "
            f"{highest_risk}/100"
        )

        if highest_risk >= 90:

            print("STATUS: CRITICAL")
            print(
                "Immediate investigation recommended."
            )

        elif highest_risk >= 70:

            print("STATUS: HIGH RISK")
            print(
                "Security investigation recommended."
            )

        elif highest_risk >= 40:

            print("STATUS: MEDIUM RISK")
            print(
                "Review detected activity."
            )

        else:

            print("STATUS: LOW RISK")


# ---------------------------------------------------------
# Program Entry Point
# ---------------------------------------------------------

if __name__ == "__main__":

    events = load_events()

    analyze_events(events)