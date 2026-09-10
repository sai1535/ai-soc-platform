import json
import os
from datetime import datetime

INPUT_FILE = "../data/alerts.json"
OUTPUT_FILE = "../reports/response_report.json"


def load_alerts():
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def determine_response(alert):
    severity = alert.get("severity", "UNKNOWN")
    risk_score = alert.get("risk_score", 0)
    threat_type = alert.get("type", "Unknown Threat")

    if severity == "CRITICAL" or risk_score >= 90:
        response_priority = "URGENT"

        actions = [
            "Investigate the affected user account immediately.",
            "Investigate the source IP address.",
            "Review authentication logs around the detected activity.",
            "Check whether a successful login occurred after the failed attempts.",
            "Check for other suspicious activity associated with the source IP.",
            "Consider account protection measures if malicious activity is confirmed."
        ]

        status = "RESPONSE_REQUIRED"

    elif severity == "HIGH" or risk_score >= 70:
        response_priority = "HIGH"

        actions = [
            "Investigate the affected user account.",
            "Review authentication logs.",
            "Investigate the source IP address.",
            "Check for successful authentication after failed attempts."
        ]

        status = "RESPONSE_REQUIRED"

    elif severity == "MEDIUM" or risk_score >= 40:
        response_priority = "MEDIUM"

        actions = [
            "Review the security alert.",
            "Check authentication activity.",
            "Monitor the affected account and source IP."
        ]

        status = "MONITOR"

    else:
        response_priority = "LOW"

        actions = [
            "Monitor the activity.",
            "Review the alert if additional suspicious events occur."
        ]

        status = "MONITOR"

    return {
        "response_id": f"RESP-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
        "timestamp": datetime.now().isoformat(),
        "threat_type": threat_type,
        "severity": severity,
        "risk_score": risk_score,
        "response_priority": response_priority,
        "response_status": status,
        "affected_user": alert.get("user", "Unknown"),
        "source_ip": alert.get("source_ip", "Unknown"),
        "failed_attempts": alert.get("failed_attempts", 0),
        "recommended_actions": actions
    }


def save_response_report(results):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\nResponse report saved to: {os.path.abspath(OUTPUT_FILE)}")


def print_results(results):
    print("\nResponse Actions:")

    if not results:
        print("No active alerts require response.")
        return

    for number, result in enumerate(results, start=1):
        print("\n" + "-" * 60)
        print(f"Response #{number}")
        print(f"Response ID: {result['response_id']}")
        print(f"Threat Type: {result['threat_type']}")
        print(f"Severity: {result['severity']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Priority: {result['response_priority']}")
        print(f"Status: {result['response_status']}")
        print(f"Affected User: {result['affected_user']}")
        print(f"Source IP: {result['source_ip']}")
        print(f"Failed Attempts: {result['failed_attempts']}")

        print("\nRecommended Actions:")
        for action in result["recommended_actions"]:
            print(f"- {action}")


def main():
    print("=" * 60)
    print("AI-Assisted SOC - Response Engine V1")
    print("=" * 60)

    alerts = load_alerts()

    print(f"\nAlerts received: {len(alerts)}")

    response_results = []

    for alert in alerts:
        response = determine_response(alert)
        response_results.append(response)

    print_results(response_results)

    save_response_report(response_results)

    print("\nResponse Engine Status:")

    if not response_results:
        print("STATUS: NO RESPONSE REQUIRED")
    else:
        urgent_count = sum(
            1 for result in response_results
            if result["response_priority"] == "URGENT"
        )

        high_count = sum(
            1 for result in response_results
            if result["response_priority"] == "HIGH"
        )

        if urgent_count > 0:
            print(f"STATUS: {urgent_count} URGENT RESPONSE(S) REQUIRED")
        elif high_count > 0:
            print(f"STATUS: {high_count} HIGH PRIORITY RESPONSE(S) REQUIRED")
        else:
            print("STATUS: MONITORING REQUIRED")


if __name__ == "__main__":
    main()