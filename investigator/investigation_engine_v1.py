import json
import os
from datetime import datetime

ALERT_FILE = "../data/alerts.json"
REPORT_FILE = "../reports/investigation_report.json"


def load_alerts():
    with open(ALERT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def investigate_alert(alert):
    severity = alert.get("severity", "UNKNOWN")
    risk_score = alert.get("risk_score", 0)

    if severity == "CRITICAL":
        priority = "URGENT"
        recommendation = (
            "Immediately investigate the affected account and source IP. "
            "Review authentication logs and consider account protection measures."
        )

    elif severity == "HIGH":
        priority = "HIGH"
        recommendation = (
            "Investigate the failed authentication activity. "
            "Review the source IP, affected account, and surrounding events."
        )

    elif severity == "MEDIUM":
        priority = "MEDIUM"
        recommendation = (
            "Review the alert and correlate it with other security events."
        )

    else:
        priority = "LOW"
        recommendation = (
            "Monitor the activity and review if additional suspicious events appear."
        )

    return {
        "alert_id": alert.get("alert_id"),
        "investigation_time": datetime.now().isoformat(),
        "threat_type": alert.get("type"),
        "severity": severity,
        "risk_score": risk_score,
        "priority": priority,
        "user": alert.get("user"),
        "source_ip": alert.get("source_ip"),
        "failed_attempts": alert.get("failed_attempts"),
        "time_window_seconds": alert.get("time_window_seconds"),
        "status": "UNDER_INVESTIGATION",
        "analyst_assessment": (
            f"Security alert identified as {severity} severity "
            f"with a risk score of {risk_score}/100."
        ),
        "recommended_action": recommendation
    }


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


def print_results(investigations):

    print("\nInvestigation Results:")

    if not investigations:
        print("No alerts available for investigation.")
        return

    for number, investigation in enumerate(
        investigations,
        start=1
    ):
        print("\n------------------------------")
        print(f"Investigation #{number}")
        print(f"Alert ID: {investigation['alert_id']}")
        print(f"Threat Type: {investigation['threat_type']}")
        print(f"Severity: {investigation['severity']}")
        print(f"Risk Score: {investigation['risk_score']}/100")
        print(f"Priority: {investigation['priority']}")
        print(f"User: {investigation['user']}")
        print(f"Source IP: {investigation['source_ip']}")
        print(
            f"Failed Attempts: "
            f"{investigation['failed_attempts']}"
        )
        print(
            f"Time Window: "
            f"{investigation['time_window_seconds']} seconds"
        )
        print(f"Status: {investigation['status']}")
        print(
            f"Assessment: "
            f"{investigation['analyst_assessment']}"
        )
        print(
            f"Recommended Action: "
            f"{investigation['recommended_action']}"
        )


def main():

    print("=" * 60)
    print("AI-Assisted SOC - Investigation Engine V1")
    print("=" * 60)

    alerts = load_alerts()

    print(f"\nAlerts received: {len(alerts)}")

    investigations = []

    for alert in alerts:
        investigation = investigate_alert(alert)
        investigations.append(investigation)

    print_results(investigations)

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "total_investigations": len(investigations),
        "investigations": investigations
    }

    save_report(report)

    print("\nInvestigation Engine Status:")

    if not investigations:
        print("STATUS: NO ACTIVE ALERTS")
    else:
        print(
            f"STATUS: {len(investigations)} "
            "ALERT(S) UNDER INVESTIGATION"
        )


if __name__ == "__main__":
    main()