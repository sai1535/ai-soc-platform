import os
import json
from collections import Counter
from datetime import datetime, timezone, timedelta


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_FILE = os.path.join(BASE_DIR, "data", "security_events.json")
ALERT_FILE = os.path.join(BASE_DIR, "data", "alerts.json")

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60

SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe"
]


# ---------------------------------------------------------
# LOAD EVENTS
# ---------------------------------------------------------

def load_events():
    if not os.path.exists(INPUT_FILE):
        print(f"Input file not found: {INPUT_FILE}")
        return []

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as error:
        print(f"Error loading events: {error}")
        return []


# ---------------------------------------------------------
# TIMESTAMP
# ---------------------------------------------------------

def parse_timestamp(timestamp):
    if not timestamp:
        return None

    try:
        timestamp = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(timestamp)

    except ValueError:
        return None


# ---------------------------------------------------------
# BASIC HELPERS
# ---------------------------------------------------------

def get_event_counts(events):
    return Counter(event.get("event_id") for event in events)


def get_event_data(event):
    return event.get("event_data", {})


def get_username(event):
    data = get_event_data(event)

    return (
        data.get("TargetUserName")
        or data.get("AccountName")
        or data.get("SubjectUserName")
        or "Unknown"
    )


def get_ip_address(event):
    data = get_event_data(event)

    return (
        data.get("IpAddress")
        or data.get("SourceIp")
        or data.get("ClientAddress")
        or "Unknown"
    )


# ---------------------------------------------------------
# DETECTION 1
# 4625 FAILED LOGON / BRUTE FORCE
# ---------------------------------------------------------

def detect_bruteforce(events):

    failed_logins = [
        event
        for event in events
        if event.get("event_id") == 4625
    ]

    alerts = []

    user_events = {}

    for event in failed_logins:

        username = get_username(event)

        if username not in user_events:
            user_events[username] = []

        user_events[username].append(event)

    for username, user_event_list in user_events.items():

        timestamped_events = []

        for event in user_event_list:

            timestamp = parse_timestamp(
                event.get("timestamp")
            )

            if timestamp:
                timestamped_events.append(
                    (timestamp, event)
                )

        timestamped_events.sort(
            key=lambda item: item[0]
        )

        for i in range(len(timestamped_events)):

            start_time = timestamped_events[i][0]

            count = 1

            for j in range(
                i + 1,
                len(timestamped_events)
            ):

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
                    "alert_id":
                        f"AUTH-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",

                    "timestamp":
                        datetime.now().isoformat(),

                    "type":
                        "Time-Window Brute Force",

                    "category":
                        "Authentication",

                    "severity":
                        severity,

                    "risk_score":
                        risk_score,

                    "user":
                        username,

                    "source_ip":
                        ip_address,

                    "failed_attempts":
                        count,

                    "time_window_seconds":
                        TIME_WINDOW_SECONDS,

                    "status":
                        "OPEN",

                    "recommended_action":
                        "Investigate",

                    "mitre_technique":
                        "T1110 - Brute Force",

                    "message":
                        f"{count} failed login attempts "
                        f"for user {username} within "
                        f"{TIME_WINDOW_SECONDS} seconds."
                })

                break

    return alerts


# ---------------------------------------------------------
# DETECTION 2
# 4688 SUSPICIOUS PROCESS CREATION
# ---------------------------------------------------------

def detect_suspicious_processes(events):

    alerts = []

    process_events = [
        event
        for event in events
        if event.get("event_id") == 4688
    ]

    for event in process_events:

        data = get_event_data(event)

        process_name = (
            data.get("NewProcessName")
            or data.get("ProcessName")
            or data.get("Image")
            or ""
        )

        process_name_lower = process_name.lower()

        matched_process = None

        for suspicious_process in SUSPICIOUS_PROCESSES:

            if suspicious_process in process_name_lower:

                matched_process = suspicious_process
                break

        if not matched_process:
            continue

        username = get_username(event)

        alert = {
            "alert_id":
                f"PROC-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",

            "timestamp":
                datetime.now().isoformat(),

            "type":
                "Suspicious Process Creation",

            "category":
                "Execution",

            "severity":
                "HIGH",

            "risk_score":
                80,

            "user":
                username,

            "process":
                process_name,

            "status":
                "OPEN",

            "recommended_action":
                "Investigate process execution",

            "mitre_technique":
                "T1059 - Command and Scripting Interpreter",

            "message":
                f"Suspicious process detected: "
                f"{process_name}"
        }

        alerts.append(alert)

    return alerts


# ---------------------------------------------------------
# DETECTION 3
# 7045 NEW SERVICE
# ---------------------------------------------------------

def detect_new_services(events):

    alerts = []

    service_events = [
        event
        for event in events
        if event.get("event_id") == 7045
    ]

    for event in service_events:

        data = get_event_data(event)

        service_name = (
            data.get("ServiceName")
            or data.get("Service_Name")
            or "Unknown"
        )

        service_file = (
            data.get("ImagePath")
            or data.get("ServiceFileName")
            or "Unknown"
        )

        alerts.append({
            "alert_id":
                f"SVC-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",

            "timestamp":
                datetime.now().isoformat(),

            "type":
                "New Windows Service",

            "category":
                "Persistence",

            "severity":
                "HIGH",

            "risk_score":
                85,

            "service_name":
                service_name,

            "service_file":
                service_file,

            "status":
                "OPEN",

            "recommended_action":
                "Investigate newly created service",

            "mitre_technique":
                "T1543.003 - Windows Service",

            "message":
                f"New Windows service detected: "
                f"{service_name}"
        })

    return alerts


# ---------------------------------------------------------
# DETECTION 4
# 1102 SECURITY LOG CLEARED
# ---------------------------------------------------------

def detect_log_cleared(events):

    alerts = []

    log_events = [
        event
        for event in events
        if event.get("event_id") == 1102
    ]

    for event in log_events:

        username = get_username(event)

        alerts.append({
            "alert_id":
                f"LOG-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",

            "timestamp":
                datetime.now().isoformat(),

            "type":
                "Security Log Cleared",

            "category":
                "Defense Evasion",

            "severity":
                "CRITICAL",

            "risk_score":
                95,

            "user":
                username,

            "status":
                "OPEN",

            "recommended_action":
                "Immediately investigate log clearing activity",

            "mitre_technique":
                "T1070.001 - Clear Windows Event Logs",

            "message":
                "Windows Security Event Log was cleared."
        })

    return alerts


# ---------------------------------------------------------
# DETECTION 5
# SUCCESSFUL LOGIN INFORMATION
# ---------------------------------------------------------

def analyze_successful_logins(events):

    successful_logins = [
        event
        for event in events
        if event.get("event_id") == 4624
    ]

    return successful_logins


# ---------------------------------------------------------
# SAVE ALERTS
# ---------------------------------------------------------

def save_alerts(alerts):

    os.makedirs(
        os.path.dirname(ALERT_FILE),
        exist_ok=True
    )

    with open(
        ALERT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4
        )

    print(
        f"\nAlerts saved to: "
        f"{os.path.abspath(ALERT_FILE)}"
    )


# ---------------------------------------------------------
# PRINT ALERTS
# ---------------------------------------------------------

def print_alerts(alerts):

    print("\nSecurity Alerts:")

    if not alerts:

        print("No suspicious activity detected.")

        return

    for number, alert in enumerate(
        alerts,
        start=1
    ):

        print("\n------------------------------")

        print(f"Alert #{number}")

        print(
            f"Alert ID: "
            f"{alert.get('alert_id', 'Unknown')}"
        )

        print(
            f"Threat: "
            f"{alert.get('type', 'Unknown')}"
        )

        print(
            f"Category: "
            f"{alert.get('category', 'Unknown')}"
        )

        print(
            f"Severity: "
            f"{alert.get('severity', 'Unknown')}"
        )

        print(
            f"Risk Score: "
            f"{alert.get('risk_score', 0)}/100"
        )

        if "user" in alert:
            print(
                f"User: "
                f"{alert.get('user')}"
            )

        if "source_ip" in alert:
            print(
                f"Source IP: "
                f"{alert.get('source_ip')}"
            )

        if "failed_attempts" in alert:
            print(
                f"Failed Attempts: "
                f"{alert.get('failed_attempts')}"
            )

        if "process" in alert:
            print(
                f"Process: "
                f"{alert.get('process')}"
            )

        if "service_name" in alert:
            print(
                f"Service: "
                f"{alert.get('service_name')}"
            )

        print(
            f"MITRE: "
            f"{alert.get('mitre_technique', 'Unknown')}"
        )

        print(
            f"Status: "
            f"{alert.get('status', 'Unknown')}"
        )

        print(
            f"Recommended Action: "
            f"{alert.get('recommended_action', 'Unknown')}"
        )

        print(
            f"Message: "
            f"{alert.get('message', '')}"
        )


# ---------------------------------------------------------
# MAIN ANALYSIS
# ---------------------------------------------------------

def analyze_events(events):

    print("=" * 65)

    print(
        "AI-Assisted SOC - Detection Engine V6"
    )

    print("=" * 65)

    print(
        f"\nTotal events analyzed: "
        f"{len(events)}"
    )

    # Event summary

    event_counts = get_event_counts(events)

    print("\nEvent Summary:")

    for event_id, count in sorted(
        event_counts.items()
    ):

        descriptions = {
            4624: "Successful Logon",
            4625: "Failed Logon",
            4688: "Process Creation",
            7045: "New Service",
            1102: "Security Log Cleared"
        }

        description = descriptions.get(
            event_id,
            "Other Event"
        )

        print(
            f"{event_id} - "
            f"{description}: "
            f"{count}"
        )

    # Run detections

    alerts = []

    alerts.extend(
        detect_bruteforce(events)
    )

    alerts.extend(
        detect_suspicious_processes(events)
    )

    alerts.extend(
        detect_new_services(events)
    )

    alerts.extend(
        detect_log_cleared(events)
    )

    # Successful login analysis

    successful_logins = analyze_successful_logins(
        events
    )

    print("\nAuthentication Analysis:")

    print(
        f"Successful Logins: "
        f"{len(successful_logins)}"
    )

    print("\nDetection Analysis:")

    print(
        f"Total Alerts Generated: "
        f"{len(alerts)}"
    )

    print_alerts(alerts)

    save_alerts(alerts)

    # Final risk

    print("\nFinal Security Assessment:")

    if not alerts:

        print("Risk Score: 0/100")
        print("STATUS: NORMAL")

    else:

        highest_risk = max(
            alert.get("risk_score", 0)
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

        else:

            print("STATUS: LOW RISK")


# ---------------------------------------------------------
# PROGRAM START
# ---------------------------------------------------------

if __name__ == "__main__":

    events = load_events()

    analyze_events(events)