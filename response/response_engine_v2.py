import os
import json
from datetime import datetime


# ================================================================
# AI-Assisted SOC - Response Engine V2
# ================================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

ALERT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "alerts.json"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "reports"
)

REPORT_FILE = os.path.join(
    REPORT_DIR,
    "response_report_v2.json"
)


# ================================================================
# Load Alerts
# ================================================================

def load_alerts():

    if not os.path.exists(ALERT_FILE):
        print("ERROR: alerts.json not found.")
        return []

    try:
        with open(
            ALERT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except Exception as error:

        print(f"ERROR loading alerts: {error}")
        return []


# ================================================================
# Determine Response Level
# ================================================================

def get_response_level(risk_score):

    if risk_score >= 90:
        return "CRITICAL_RESPONSE"

    elif risk_score >= 80:
        return "HIGH_RESPONSE"

    elif risk_score >= 60:
        return "MEDIUM_RESPONSE"

    elif risk_score >= 40:
        return "LOW_RESPONSE"

    return "MONITOR"


# ================================================================
# Generate Response Actions
# ================================================================

def generate_actions(alert):

    risk_score = alert.get(
        "risk_score",
        0
    )

    username = alert.get(
        "username",
        alert.get("user", "Unknown")
    )

    source_ip = alert.get(
        "source_ip",
        "Unknown"
    )

    actions = []

    if risk_score >= 90:

        actions = [

            {
                "priority": 1,
                "action": "Investigate affected account",
                "reason": f"Possible compromise of user {username}"
            },

            {
                "priority": 2,
                "action": "Investigate source IP",
                "reason": f"Suspicious activity originated from {source_ip}"
            },

            {
                "priority": 3,
                "action": "Review authentication logs",
                "reason": "Identify additional failed and successful logins"
            },

            {
                "priority": 4,
                "action": "Review process execution",
                "reason": "Determine whether malicious processes were executed"
            },

            {
                "priority": 5,
                "action": "Review persistence activity",
                "reason": "Check for newly created services or other persistence"
            },

            {
                "priority": 6,
                "action": "Search for related activity",
                "reason": "Determine whether the same source affected other accounts or hosts"
            },

            {
                "priority": 7,
                "action": "Consider account protection",
                "reason": "Contain the account if compromise is confirmed"
            }

        ]

    elif risk_score >= 60:

        actions = [

            {
                "priority": 1,
                "action": "Investigate alert",
                "reason": "Elevated security risk detected"
            },

            {
                "priority": 2,
                "action": "Review authentication logs",
                "reason": "Identify suspicious login activity"
            },

            {
                "priority": 3,
                "action": "Investigate source IP",
                "reason": "Determine origin of suspicious activity"
            },

            {
                "priority": 4,
                "action": "Monitor affected account",
                "reason": "Look for additional suspicious behavior"
            }

        ]

    elif risk_score >= 40:

        actions = [

            {
                "priority": 1,
                "action": "Review alert",
                "reason": "Moderate security risk detected"
            },

            {
                "priority": 2,
                "action": "Monitor related activity",
                "reason": "Look for repeated suspicious behavior"
            }

        ]

    else:

        actions = [

            {
                "priority": 1,
                "action": "Monitor",
                "reason": "Low-risk activity"
            }

        ]

    return actions


# ================================================================
# Build Response
# ================================================================

def build_response(alert, response_id):

    risk_score = alert.get(
        "risk_score",
        0
    )

    severity = alert.get(
        "severity",
        "UNKNOWN"
    )

    threat_type = alert.get(
        "threat_type",
        "Suspicious Security Activity"
    )

    username = alert.get(
        "username",
        alert.get("user", "Unknown")
    )

    source_ip = alert.get(
        "source_ip",
        "Unknown"
    )

    response_level = get_response_level(
        risk_score
    )

    actions = generate_actions(
        alert
    )

    if risk_score >= 90:

        status = "RESPONSE_REQUIRED"

    elif risk_score >= 60:

        status = "ANALYST_REVIEW_REQUIRED"

    else:

        status = "MONITORING"

    return {

        "response_id": response_id,

        "generated_at": datetime.now().isoformat(),

        "status": status,

        "response_level": response_level,

        "severity": severity,

        "risk_score": risk_score,

        "threat_type": threat_type,

        "affected_user": username,

        "source_ip": source_ip,

        "recommended_actions": actions

    }


# ================================================================
# Save Report
# ================================================================

def save_report(responses):

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    report = {

        "generated_at": datetime.now().isoformat(),

        "total_responses": len(responses),

        "responses": responses

    }

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


# ================================================================
# Main
# ================================================================

def main():

    print("=" * 65)
    print("AI-Assisted SOC - Response Engine V2")
    print("=" * 65)

    alerts = load_alerts()

    print(
        f"\nTotal alerts received: {len(alerts)}"
    )

    if not alerts:

        print(
            "\nNo alerts requiring response."
        )

        save_report([])

        print(
            f"\nResponse report saved to:"
            f"\n{REPORT_FILE}"
        )

        return

    responses = []

    for index, alert in enumerate(
        alerts,
        start=1
    ):

        response = build_response(
            alert,
            f"RESP-{index:04d}"
        )

        responses.append(
            response
        )

        print(
            f"\nResponse #{index}"
        )

        print(
            f"Threat: "
            f"{response['threat_type']}"
        )

        print(
            f"Severity: "
            f"{response['severity']}"
        )

        print(
            f"Risk Score: "
            f"{response['risk_score']}/100"
        )

        print(
            f"Response Level: "
            f"{response['response_level']}"
        )

        print(
            f"Status: "
            f"{response['status']}"
        )

        print("\nRecommended Actions:")

        for action in response["recommended_actions"]:

            print(
                f"  {action['priority']}. "
                f"{action['action']}"
            )

    save_report(
        responses
    )

    print("\n" + "=" * 65)

    print(
        f"Total responses generated: "
        f"{len(responses)}"
    )

    print(
        f"Response report saved to:"
        f"\n{REPORT_FILE}"
    )

    print("=" * 65)


# ================================================================
# Program Start
# ================================================================

if __name__ == "__main__":
    main()