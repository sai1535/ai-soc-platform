import json
import os
from datetime import datetime

ALERT_FILE = "../data/alerts.json"
REPORT_FILE = "../reports/investigation_report_v2.json"


def load_alerts():
    with open(ALERT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def determine_attack_type(alert):
    threat_type = alert.get("type", "").lower()

    if "brute force" in threat_type:
        return "Authentication Brute Force Attack"

    return "Suspicious Security Activity"


def determine_confidence(alert):
    severity = alert.get("severity", "")
    failed_attempts = alert.get("failed_attempts", 0)

    if severity == "CRITICAL" and failed_attempts >= 10:
        return "HIGH"

    elif severity == "HIGH":
        return "MEDIUM"

    return "LOW"


def generate_evidence(alert):

    evidence = []

    if alert.get("user"):
        evidence.append(
            f"Target account: {alert.get('user')}"
        )

    if alert.get("source_ip"):
        evidence.append(
            f"Source IP: {alert.get('source_ip')}"
        )

    if alert.get("failed_attempts"):
        evidence.append(
            f"Failed authentication attempts: "
            f"{alert.get('failed_attempts')}"
        )

    if alert.get("time_window_seconds"):
        evidence.append(
            f"Detection window: "
            f"{alert.get('time_window_seconds')} seconds"
        )

    return evidence


def generate_timeline(alert):

    return [
        {
            "stage": "Detection",
            "description": (
                f"{alert.get('failed_attempts')} failed login "
                f"attempts detected for user "
                f"{alert.get('user')}."
            )
        },
        {
            "stage": "Correlation",
            "description": (
                f"Authentication attempts were correlated "
                f"within a {alert.get('time_window_seconds')} "
                f"second time window."
            )
        },
        {
            "stage": "Risk Assessment",
            "description": (
                f"Activity received a risk score of "
                f"{alert.get('risk_score')}/100."
            )
        },
        {
            "stage": "Investigation",
            "description": (
                "Security analyst investigation recommended."
            )
        }
    ]


def generate_recommendations(alert):

    severity = alert.get("severity")

    if severity == "CRITICAL":

        return [
            "Investigate the affected account immediately.",
            "Review authentication logs around the detected activity.",
            "Investigate the source IP address.",
            "Check whether successful login occurred after the failures.",
            "Consider account protection measures if malicious activity is confirmed."
        ]

    elif severity == "HIGH":

        return [
            "Review the affected account.",
            "Investigate the source IP.",
            "Review surrounding authentication events.",
            "Monitor for additional suspicious activity."
        ]

    return [
        "Monitor the activity.",
        "Review related security events."
    ]


def investigate_alert(alert):

    severity = alert.get("severity", "UNKNOWN")
    risk_score = alert.get("risk_score", 0)

    if severity == "CRITICAL":
        priority = "URGENT"

    elif severity == "HIGH":
        priority = "HIGH"

    elif severity == "MEDIUM":
        priority = "MEDIUM"

    else:
        priority = "LOW"

    investigation = {
        "investigation_id": (
            f"INV-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ),
        "investigation_time": datetime.now().isoformat(),

        "alert_id": alert.get("alert_id"),

        "attack_classification": determine_attack_type(alert),

        "severity": severity,

        "risk_score": risk_score,

        "priority": priority,

        "confidence": determine_confidence(alert),

        "affected_user": alert.get("user"),

        "source_ip": alert.get("source_ip"),

        "failed_attempts": alert.get("failed_attempts"),

        "time_window_seconds": alert.get(
            "time_window_seconds"
        ),

        "status": "UNDER_INVESTIGATION",

        "evidence": generate_evidence(alert),

        "timeline": generate_timeline(alert),

        "analyst_finding": (
            f"The system detected suspicious authentication "
            f"activity involving user "
            f"{alert.get('user')} from source IP "
            f"{alert.get('source_ip')}. "
            f"{alert.get('failed_attempts')} failed login "
            f"attempts occurred within "
            f"{alert.get('time_window_seconds')} seconds. "
            f"The activity is classified as "
            f"{determine_attack_type(alert)}."
        ),

        "recommended_actions": generate_recommendations(
            alert
        )
    }

    return investigation


def save_report(report):

    os.makedirs(
        os.path.dirname(REPORT_FILE),
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        f"\nInvestigation report saved to: "
        f"{os.path.abspath(REPORT_FILE)}"
    )


def print_investigation(investigation):

    print("\n" + "-" * 60)

    print(
        f"Investigation ID: "
        f"{investigation['investigation_id']}"
    )

    print(
        f"Attack Classification: "
        f"{investigation['attack_classification']}"
    )

    print(
        f"Severity: "
        f"{investigation['severity']}"
    )

    print(
        f"Risk Score: "
        f"{investigation['risk_score']}/100"
    )

    print(
        f"Priority: "
        f"{investigation['priority']}"
    )

    print(
        f"Confidence: "
        f"{investigation['confidence']}"
    )

    print(
        f"Affected User: "
        f"{investigation['affected_user']}"
    )

    print(
        f"Source IP: "
        f"{investigation['source_ip']}"
    )

    print(
        f"Failed Attempts: "
        f"{investigation['failed_attempts']}"
    )

    print(
        f"Time Window: "
        f"{investigation['time_window_seconds']} seconds"
    )

    print(
        f"Status: "
        f"{investigation['status']}"
    )

    print("\nEvidence:")

    for evidence in investigation["evidence"]:
        print(f"- {evidence}")

    print("\nTimeline:")

    for event in investigation["timeline"]:
        print(
            f"- {event['stage']}: "
            f"{event['description']}"
        )

    print("\nAnalyst Finding:")

    print(
        investigation["analyst_finding"]
    )

    print("\nRecommended Actions:")

    for action in investigation["recommended_actions"]:
        print(f"- {action}")


def main():

    print("=" * 60)
    print("AI-Assisted SOC - Investigation Engine V2")
    print("=" * 60)

    alerts = load_alerts()

    print(
        f"\nAlerts received: "
        f"{len(alerts)}"
    )

    investigations = []

    for alert in alerts:

        investigation = investigate_alert(
            alert
        )

        investigations.append(
            investigation
        )

    if not investigations:

        print(
            "\nNo active alerts available "
            "for investigation."
        )

    else:

        for investigation in investigations:

            print_investigation(
                investigation
            )

    report = {
        "generated_at": datetime.now().isoformat(),
        "engine": "Investigation Engine V2",
        "total_alerts": len(alerts),
        "total_investigations": len(
            investigations
        ),
        "investigations": investigations
    }

    save_report(report)

    print("\nInvestigation Engine Status:")

    if not investigations:

        print(
            "STATUS: NO ACTIVE ALERTS"
        )

    else:

        print(
            f"STATUS: {len(investigations)} "
            f"ALERT(S) UNDER INVESTIGATION"
        )


if __name__ == "__main__":
    main()