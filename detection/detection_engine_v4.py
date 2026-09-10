import json
from collections import Counter
from datetime import datetime

INPUT_FILE = "../data/security_events.json"

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


def load_events():
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_timestamp(timestamp):
    if not timestamp:
        return None

    try:
        # Windows timestamps commonly end with Z
        timestamp = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def get_event_counts(events):
    return Counter(
        event.get("event_id")
        for event in events
    )


def get_failed_logins(events):
    return [
        event
        for event in events
        if event.get("event_id") == 4625
    ]


def get_username(event):
    event_data = event.get("event_data", {})

    return (
        event_data.get("TargetUserName")
        or event_data.get("AccountName")
        or "Unknown"
    )


def get_ip_address(event):
    event_data = event.get("event_data", {})

    return (
        event_data.get("IpAddress")
        or "Unknown"
    )


def detect_time_window_bruteforce(events):
    failed_logins = get_failed_logins(events)

    alerts = []

    # Group failed logins by user
    user_events = {}

    for event in failed_logins:
        username = get_username(event)

        if username not in user_events:
            user_events[username] = []

        user_events[username].append(event)

    # Analyze each user
    for username, events_for_user in user_events.items():

        timestamped_events = []

        for event in events_for_user:
            timestamp = parse_timestamp(
                event.get("timestamp")
            )

            if timestamp:
                timestamped_events.append(
                    (timestamp, event)
                )

        timestamped_events.sort(
            key=lambda x: x[0]
        )

        # Sliding time window
        for i in range(len(timestamped_events)):

            start_time = timestamped_events[i][0]

            count = 1

            for j in range(i + 1, len(timestamped_events)):

                current_time = timestamped_events[j][0]

                difference = (
                    current_time - start_time
                ).total_seconds()

                if difference <= TIME_WINDOW_SECONDS:
                    count += 1
                else:
                    break

            if count >= FAILED_LOGIN_THRESHOLD:

                first_event = timestamped_events[i][1]

                ip_address = get_ip_address(
                    first_event
                )

                if count >= 10:
                    severity = "CRITICAL"
                    risk_score = 95

                else:
                    severity = "HIGH"
                    risk_score = 75

                alerts.append({
                    "type": "Time-Window Brute Force",
                    "severity": severity,
                    "risk_score": risk_score,
                    "user": username,
                    "ip": ip_address,
                    "attempts": count,
                    "window": TIME_WINDOW_SECONDS,
                    "message": (
                        f"{count} failed login attempts "
                        f"for user {username} within "
                        f"{TIME_WINDOW_SECONDS} seconds."
                    )
                })

                # One alert per user is enough
                break

    return alerts


def print_alerts(alerts):

    print("\nSecurity Alerts:")

    if not alerts:
        print("No time-window attack patterns detected.")
        return

    for number, alert in enumerate(alerts, start=1):

        print("\n------------------------------")
        print(f"Alert #{number}")

        print(f"Threat: {alert['type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Risk Score: {alert['risk_score']}/100")

        print(f"User: {alert['user']}")
        print(f"Source IP: {alert['ip']}")

        print(f"Failed Attempts: {alert['attempts']}")
        print(
            f"Time Window: "
            f"{alert['window']} seconds"
        )

        print(f"Message: {alert['message']}")

        print(
            "Recommended Action: Investigate"
        )


def analyze_events(events):

    print("=" * 60)
    print("AI-Assisted SOC - Detection Engine V4")
    print("=" * 60)

    print(
        f"\nTotal events analyzed: {len(events)}"
    )

    # Event summary
    event_counts = get_event_counts(events)

    print("\nEvent Summary:")

    for event_id, count in sorted(
        event_counts.items()
    ):

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

    # Time-window detection
    print("\nBehavioral Analysis:")

    alerts = detect_time_window_bruteforce(
        events
    )

    if not alerts:

        print(
            "No suspicious time-window "
            "authentication patterns detected."
        )

    else:

        print(
            f"Suspicious patterns detected: "
            f"{len(alerts)}"
        )

    print_alerts(alerts)

    # Final assessment
    print("\nFinal Security Assessment:")

    if not alerts:

        print("Risk Score: 0/100")
        print("STATUS: NORMAL")

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

        else:

            print("STATUS: LOW RISK")


if __name__ == "__main__":

    events = load_events()

    analyze_events(events)