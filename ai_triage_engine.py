import json
import os


# ============================================================
# AI-ASSISTED SOC - ALERT TRIAGE ENGINE V1
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ALERT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "alerts.json"
)

TRIAGE_REPORT = os.path.join(
    BASE_DIR,
    "reports",
    "ai_triage_report.json"
)


# ------------------------------------------------------------
# Load alerts
# ------------------------------------------------------------

def load_alerts():

    if not os.path.exists(ALERT_FILE):
        print("alerts.json not found.")
        return []

    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as error:
        print(f"Error reading alerts.json: {error}")
        return []


# ------------------------------------------------------------
# AI-style triage logic
# ------------------------------------------------------------

def triage_alert(alert):

    risk_score = alert.get("risk_score", 0)
    severity = alert.get("severity", "UNKNOWN")

    attack_chain = alert.get("attack_chain", [])
    evidence = alert.get("evidence", [])

    username = alert.get("username", "Unknown")
    source_ip = alert.get("source_ip", "Unknown")

    # Count important attack indicators
    indicator_count = len(evidence)

    # --------------------------------------------------------
    # Triage decision
    # --------------------------------------------------------

    if risk_score >= 90 and indicator_count >= 3:

        classification = "TRUE POSITIVE"
        confidence = "HIGH"

        explanation = (
            "Multiple correlated security indicators were detected. "
            "The alert contains authentication failures followed by "
            "successful authentication, process execution, and persistence."
        )

        priority = "URGENT"

        recommended_action = [
            "Investigate the affected account",
            "Investigate the source IP",
            "Review authentication activity",
            "Review PowerShell/process execution",
            "Investigate persistence activity",
            "Search for related security events"
        ]

    elif risk_score >= 60:

        classification = "NEEDS REVIEW"
        confidence = "MEDIUM"

        explanation = (
            "The alert contains suspicious activity and requires "
            "additional analyst investigation before confirming the threat."
        )

        priority = "HIGH"

        recommended_action = [
            "Review authentication events",
            "Review source IP activity",
            "Check related events",
            "Investigate affected user"
        ]

    else:

        classification = "LIKELY FALSE POSITIVE"
        confidence = "LOW"

        explanation = (
            "The available evidence does not currently provide "
            "enough indicators to confirm a significant security threat."
        )

        priority = "LOW"

        recommended_action = [
            "Review alert context",
            "Check whether the activity is expected",
            "Close alert if confirmed benign"
        ]

    # --------------------------------------------------------
    # Build triage result
    # --------------------------------------------------------

    result = {
        "alert_id": alert.get("alert_id"),
        "classification": classification,
        "confidence": confidence,
        "priority": priority,
        "risk_score": risk_score,
        "severity": severity,

        "username": username,
        "source_ip": source_ip,

        "attack_chain": attack_chain,
        "evidence": evidence,

        "ai_explanation": explanation,

        "recommended_actions": recommended_action,

        "triage_engine": "AI-Assisted Triage V1",
        "status": "TRIAGED"
    }

    return result


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    print("=" * 60)
    print("AI-ASSISTED SOC - ALERT TRIAGE ENGINE V1")
    print("=" * 60)

    alerts = load_alerts()

    print(f"\nTotal alerts received: {len(alerts)}")

    triage_results = []

    for index, alert in enumerate(alerts, start=1):

        result = triage_alert(alert)

        triage_results.append(result)

        print(f"\nTriage #{index}")
        print(f"Threat: {alert.get('threat_type', 'Unknown')}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Severity: {result['severity']}")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Priority: {result['priority']}")

        print("\nAI Explanation:")
        print(f"  {result['ai_explanation']}")

        print("\nRecommended Actions:")

        for action_number, action in enumerate(
            result["recommended_actions"],
            start=1
        ):
            print(f"  {action_number}. {action}")

    # --------------------------------------------------------
    # Save report
    # --------------------------------------------------------

    os.makedirs(
        os.path.dirname(TRIAGE_REPORT),
        exist_ok=True
    )

    with open(
        TRIAGE_REPORT,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            triage_results,
            file,
            indent=4
        )

    print("\n" + "=" * 60)
    print(f"Triage results generated: {len(triage_results)}")
    print(f"Report saved to:")
    print(TRIAGE_REPORT)
    print("=" * 60)


if __name__ == "__main__":
    main()