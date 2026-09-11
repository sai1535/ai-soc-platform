import os
import json
from datetime import datetime
from collections import Counter


# ============================================================
# AI-Assisted SOC Platform
# Detection & Correlation Engine V7
# ============================================================


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# ------------------------------------------------------------
# TEST DATASET
# Use this for testing the V7 correlation engine.
# After successful testing, change this to security_events.json
# ------------------------------------------------------------

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "test_v7_security_events.json"
)

ALERT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "alerts.json"
)


# ============================================================
# LOAD EVENTS
# ============================================================

def load_events():

    if not os.path.exists(INPUT_FILE):
        print(f"Input file not found: {INPUT_FILE}")
        return []

    try:

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):

            print(
                "Error: Security event data is not a list."
            )

            return []

        return data

    except Exception as error:

        print(
            f"Error loading events: {error}"
        )

        return []


# ============================================================
# SAVE ALERTS
# ============================================================

def save_alerts(alerts):

    try:

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

    except Exception as error:

        print(
            f"Error saving alerts: {error}"
        )


# ============================================================
# EVENT SUMMARY
# ============================================================

def get_event_counts(events):

    return Counter(
        event.get("event_id")
        for event in events
        if isinstance(event, dict)
    )


# ============================================================
# NORMALIZE TIMESTAMP
# ============================================================

def parse_timestamp(value):

    if not value:
        return None

    try:

        return datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00"
            )
        )

    except Exception:

        return None


# ============================================================
# EXTRACT EVENT INFORMATION
# ============================================================

def extract_event_info(event):

    if not isinstance(event, dict):
        return {}

    event_id = event.get("event_id")

    timestamp = (
        event.get("timestamp")
        or event.get("time")
        or event.get("event_time")
    )

    username = (
        event.get("username")
        or event.get("user")
        or event.get("target_username")
        or event.get("account_name")
    )

    source_ip = (
        event.get("source_ip")
        or event.get("ip_address")
        or event.get("src_ip")
    )

    process_name = (
        event.get("process_name")
        or event.get("process")
        or event.get("image")
    )

    service_name = (
        event.get("service_name")
        or event.get("service")
    )

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "datetime": parse_timestamp(timestamp),
        "username": username,
        "source_ip": source_ip,
        "process_name": process_name,
        "service_name": service_name
    }


# ============================================================
# CORRELATION ENGINE
# ============================================================

def correlate_events(events):

    normalized_events = []

    # --------------------------------------------------------
    # Normalize all events
    # --------------------------------------------------------

    for event in events:

        info = extract_event_info(event)

        if info:

            normalized_events.append(info)

    # --------------------------------------------------------
    # Sort events by timestamp
    # --------------------------------------------------------

    normalized_events.sort(
        key=lambda x: x["datetime"] or datetime.min
    )

    correlations = []

    # --------------------------------------------------------
    # Look for attack chain:
    #
    # 4625 Failed Login
    #       ↓
    # 4624 Successful Login
    #       ↓
    # 4688 Process Creation
    #       ↓
    # 7045 New Windows Service
    #
    # Time window: 10 minutes
    # --------------------------------------------------------

    for index, event in enumerate(normalized_events):

        # Only failed-login events can start
        # an authentication attack chain.

        if event["event_id"] != 4625:
            continue

        # ----------------------------------------------------
        # Avoid duplicate correlations
        #
        # If the previous event is another failed login
        # from the same user and IP, this is part of the
        # same attack sequence.
        # ----------------------------------------------------

        previous_failed = False

        if index > 0:

            previous_event = normalized_events[index - 1]

            if (
                previous_event["event_id"] == 4625
                and
                previous_event["username"] == event["username"]
                and
                previous_event["source_ip"] == event["source_ip"]
            ):

                previous_failed = True

        if previous_failed:
            continue

        # ----------------------------------------------------
        # Starting event information
        # ----------------------------------------------------

        failed_time = event["datetime"]

        failed_user = event["username"]

        failed_ip = event["source_ip"]

        failed_count = 1

        success_event = None

        process_event = None

        service_event = None

        # ----------------------------------------------------
        # Search next events within 10 minutes
        # ----------------------------------------------------

        for next_event in normalized_events[index + 1:]:

            next_time = next_event["datetime"]

            if next_time is None:

                continue

            if failed_time is None:

                continue

            time_difference = (
                next_time - failed_time
            ).total_seconds()

            if time_difference < 0:

                continue

            if time_difference > 600:

                break

            # ------------------------------------------------
            # Failed login
            # ------------------------------------------------

            if (
                next_event["event_id"] == 4625
                and
                (
                    not failed_user
                    or
                    next_event["username"] == failed_user
                )
                and
                (
                    not failed_ip
                    or
                    next_event["source_ip"] == failed_ip
                )
            ):

                failed_count += 1

            # ------------------------------------------------
            # Successful login
            # ------------------------------------------------

            elif (
                next_event["event_id"] == 4624
                and
                (
                    not failed_user
                    or
                    next_event["username"] == failed_user
                )
            ):

                if success_event is None:

                    success_event = next_event

            # ------------------------------------------------
            # Process creation
            # ------------------------------------------------

            elif next_event["event_id"] == 4688:

                if process_event is None:

                    process_event = next_event

            # ------------------------------------------------
            # New Windows service
            # ------------------------------------------------

            elif next_event["event_id"] == 7045:

                if service_event is None:

                    service_event = next_event

        # ----------------------------------------------------
        # Calculate correlation score
        # ----------------------------------------------------

        score = 0

        evidence = []

        attack_chain = []

        # ----------------------------------------------------
        # Authentication failures
        # ----------------------------------------------------

        if failed_count >= 5:

            score += 40

            evidence.append(
                f"{failed_count} failed login attempts detected"
            )

            attack_chain.append(
                "Authentication Failures"
            )

        # ----------------------------------------------------
        # Successful authentication
        # ----------------------------------------------------

        if success_event:

            score += 20

            evidence.append(
                "Successful login detected after failed attempts"
            )

            attack_chain.append(
                "Successful Authentication"
            )

        # ----------------------------------------------------
        # Process execution
        # ----------------------------------------------------

        if process_event:

            score += 20

            process_name = process_event.get(
                "process_name"
            )

            if process_name:

                evidence.append(
                    f"Process creation detected: {process_name}"
                )

            else:

                evidence.append(
                    "Process creation detected"
                )

            attack_chain.append(
                "Process Execution"
            )

        # ----------------------------------------------------
        # Persistence
        # ----------------------------------------------------

        if service_event:

            score += 20

            service_name = service_event.get(
                "service_name"
            )

            if service_name:

                evidence.append(
                    f"New Windows service detected: {service_name}"
                )

            else:

                evidence.append(
                    "New Windows service detected"
                )

            attack_chain.append(
                "Persistence"
            )

        # ----------------------------------------------------
        # Generate correlation only when meaningful
        # ----------------------------------------------------

        if score < 40:

            continue

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        if score >= 80:

            severity = "CRITICAL"

        elif score >= 60:

            severity = "HIGH"

        else:

            severity = "MEDIUM"

        # ----------------------------------------------------
        # Threat type
        # ----------------------------------------------------

        if (
            success_event
            and
            process_event
            and
            service_event
        ):

            threat_type = (
                "Possible Account Compromise "
                "with Execution and Persistence"
            )

        elif (
            success_event
            and
            process_event
        ):

            threat_type = (
                "Possible Account Compromise "
                "with Process Execution"
            )

        elif success_event:

            threat_type = (
                "Possible Account Compromise"
            )

        else:

            threat_type = (
                "Authentication Attack"
            )

        # ----------------------------------------------------
        # Create alert
        # ----------------------------------------------------

        alert = {

            "alert_id": (
                "CORR-"
                +
                datetime.now().strftime(
                    "%Y%m%d%H%M%S%f"
                )
            ),

            "threat_type": threat_type,

            "severity": severity,

            "risk_score": score,

            "username": failed_user,

            "source_ip": failed_ip,

            "failed_attempts": failed_count,

            "attack_chain": attack_chain,

            "evidence": evidence,

            "status": "OPEN",

            "detection_engine": "V7",

            "recommended_action": (
                "Investigate authentication activity, "
                "process execution and persistence indicators."
            )
        }

        correlations.append(alert)

    return correlations


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_events(events):

    print()

    print("=" * 65)

    print(
        "AI-Assisted SOC - Detection & Correlation Engine V7"
    )

    print("=" * 65)

    print()

    # --------------------------------------------------------
    # Total events
    # --------------------------------------------------------

    print(
        f"Total events analyzed: {len(events)}"
    )

    print()

    # --------------------------------------------------------
    # Event summary
    # --------------------------------------------------------

    event_counts = get_event_counts(events)

    print("Event Summary:")

    event_names = {

        4624: "Successful Logon",

        4625: "Failed Logon",

        4688: "Process Creation",

        7045: "New Windows Service",

        1102: "Security Log Cleared"

    }

    for event_id, count in sorted(
        event_counts.items()
    ):

        name = event_names.get(
            event_id,
            "Unknown Event"
        )

        print(
            f"{event_id} - {name}: {count}"
        )

    print()

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    print("Correlation Analysis:")

    alerts = correlate_events(events)

    if not alerts:

        print(
            "No multi-stage attack chains detected."
        )

    else:

        print(
            f"Correlated attack chains: {len(alerts)}"
        )

        print()

        for number, alert in enumerate(
            alerts,
            start=1
        ):

            print(
                f"Correlation #{number}"
            )

            print(
                f"Threat Type: {alert['threat_type']}"
            )

            print(
                f"Severity: {alert['severity']}"
            )

            print(
                f"Risk Score: {alert['risk_score']}/100"
            )

            print(
                f"User: {alert['username']}"
            )

            print(
                f"Source IP: {alert['source_ip']}"
            )

            print(
                f"Failed Attempts: {alert['failed_attempts']}"
            )

            print()

            print("Attack Chain:")

            for step in alert["attack_chain"]:

                print(
                    f"  → {step}"
                )

            print()

            print("Evidence:")

            for item in alert["evidence"]:

                print(
                    f"  - {item}"
                )

            print()

    # --------------------------------------------------------
    # Save alerts
    # --------------------------------------------------------

    save_alerts(alerts)

    print(
        f"Alerts saved to: {ALERT_FILE}"
    )

    print()

    # --------------------------------------------------------
    # Final risk
    # --------------------------------------------------------

    if alerts:

        max_risk = max(
            alert["risk_score"]
            for alert in alerts
        )

    else:

        max_risk = 0

    print("Final Security Assessment:")

    print(
        f"Risk Score: {max_risk}/100"
    )

    if max_risk >= 80:

        print(
            "STATUS: CRITICAL"
        )

    elif max_risk >= 60:

        print(
            "STATUS: HIGH"
        )

    elif max_risk >= 40:

        print(
            "STATUS: MEDIUM"
        )

    else:

        print(
            "STATUS: NORMAL"
        )

    print()


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    events = load_events()

    analyze_events(events)