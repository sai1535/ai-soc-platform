import json
import os
from datetime import datetime

# ================================================================
# AI-Assisted SOC - Investigation Engine V3.2
# MITRE ATT&CK Integrated Investigation
# ================================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

ALERT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "alerts.json"
)

MITRE_FILE = os.path.join(
    BASE_DIR,
    "config",
    "mitre_attack_mapping.json"
)

REPORT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "investigation_report_v3.json"
)


# ================================================================
# LOAD JSON
# ================================================================

def load_json(file_path, default):

    try:

        if not os.path.exists(file_path):
            return default

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            f"Error reading {file_path}: {error}"
        )

        return default


# ================================================================
# MITRE MAPPING
# ================================================================

def get_mitre_mapping(
    attack_chain,
    threat_type,
    mitre_mapping
):

    techniques = []

    # Authentication / Brute Force
    if "Authentication Failures" in attack_chain:

        techniques.append(
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access"
            }
        )

    # PowerShell / Process Execution
    if "Process Execution" in attack_chain:

        techniques.append(
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "Execution"
            }
        )

    # Windows Service / Persistence
    if "Persistence" in attack_chain:

        techniques.append(
            {
                "technique_id": "T1543.003",
                "technique_name": "Windows Service",
                "tactic": "Persistence"
            }
        )

    # Fallback
    if not techniques:

        mapping = mitre_mapping.get(
            threat_type,
            mitre_mapping.get(
                "Authentication Attack",
                {}
            )
        )

        if mapping:

            techniques.append(mapping)

    return techniques


# ================================================================
# PRIORITY
# ================================================================

def determine_priority(risk_score):

    if risk_score >= 90:
        return "URGENT"

    elif risk_score >= 70:
        return "HIGH"

    elif risk_score >= 40:
        return "MEDIUM"

    return "LOW"


# ================================================================
# CONFIDENCE
# ================================================================

def determine_confidence(risk_score):

    if risk_score >= 90:
        return "HIGH"

    elif risk_score >= 60:
        return "MEDIUM"

    return "LOW"


# ================================================================
# EVIDENCE
# ================================================================

def build_evidence(alert):

    # V7 already provides the evidence.
    evidence = alert.get(
        "evidence",
        []
    )

    return evidence


# ================================================================
# ATTACK CHAIN
# ================================================================

def build_attack_chain(alert):

    # V7 already provides the complete attack chain.
    attack_chain = alert.get(
        "attack_chain",
        []
    )

    return attack_chain


# ================================================================
# TIMELINE
# ================================================================

def build_timeline(
    alert,
    attack_chain,
    risk_score
):

    timeline = []

    if "Authentication Failures" in attack_chain:

        timeline.append(
            {
                "stage": "Detection",
                "description":
                    f"{alert.get('failed_attempts', 0)} "
                    "failed authentication attempts detected."
            }
        )

    if "Successful Authentication" in attack_chain:

        timeline.append(
            {
                "stage": "Correlation",
                "description":
                    "Successful authentication occurred "
                    "after the failed login attempts."
            }
        )

    if "Process Execution" in attack_chain:

        timeline.append(
            {
                "stage": "Execution",
                "description":
                    "Process execution was detected "
                    "following authentication activity."
            }
        )

    if "Persistence" in attack_chain:

        timeline.append(
            {
                "stage": "Persistence",
                "description":
                    "A new Windows service was detected, "
                    "indicating possible persistence."
            }
        )

    timeline.append(
        {
            "stage": "Risk Assessment",
            "description":
                f"Activity received a risk score of "
                f"{risk_score}/100."
        }
    )

    timeline.append(
        {
            "stage": "Investigation",
            "description":
                "Security analyst investigation recommended."
        }
    )

    return timeline


# ================================================================
# ANALYST FINDING
# ================================================================

def build_analyst_finding(
    alert,
    attack_chain,
    mitre_techniques
):

    username = alert.get(
        "username",
        "Unknown"
    )

    source_ip = alert.get(
        "source_ip",
        "Unknown"
    )

    failed_attempts = alert.get(
        "failed_attempts",
        0
    )

    threat_type = alert.get(
        "threat_type",
        "Unknown"
    )

    finding = (
        f"The system detected suspicious activity "
        f"involving user {username} from source IP "
        f"{source_ip}. "
        f"{failed_attempts} failed authentication "
        f"attempts were detected."
    )

    if "Successful Authentication" in attack_chain:

        finding += (
            " A successful authentication occurred "
            "after the failed attempts."
        )

    if "Process Execution" in attack_chain:

        finding += (
            " Process execution was detected."
        )

    if "Persistence" in attack_chain:

        finding += (
            " A new Windows service was detected, "
            "indicating possible persistence."
        )

    finding += (
        f" The activity is classified as "
        f"{threat_type}."
    )

    if mitre_techniques:

        technique_names = ", ".join(
            [
                f"{item['technique_id']} - "
                f"{item['technique_name']}"
                for item in mitre_techniques
            ]
        )

        finding += (
            f" Associated MITRE ATT&CK techniques: "
            f"{technique_names}."
        )

    return finding


# ================================================================
# RECOMMENDED ACTIONS
# ================================================================

def build_recommended_actions(
    attack_chain
):

    actions = [
        "Investigate the affected account",
        "Investigate the source IP address",
        "Review authentication logs"
    ]

    if "Process Execution" in attack_chain:

        actions.append(
            "Review process execution activity"
        )

    if "Persistence" in attack_chain:

        actions.append(
            "Review Windows service and persistence activity"
        )

    actions.extend(
        [
            "Search for related activity",
            "Check for additional suspicious authentication",
            "Consider account protection measures if malicious activity is confirmed"
        ]
    )

    return actions


# ================================================================
# MAIN
# ================================================================

def main():

    print("=" * 65)

    print(
        "AI-Assisted SOC - Investigation Engine V3.2"
    )

    print(
        "MITRE ATT&CK Integrated Investigation"
    )

    print("=" * 65)

    alerts = load_json(
        ALERT_FILE,
        []
    )

    mitre_mapping = load_json(
        MITRE_FILE,
        {}
    )

    print()

    print(
        f"Total alerts received: {len(alerts)}"
    )

    investigations = []

    if not alerts:

        print()

        print(
            "No alerts available for investigation."
        )

    else:

        for index, alert in enumerate(
            alerts,
            start=1
        ):

            threat_type = alert.get(
                "threat_type",
                "Authentication Attack"
            )

            severity = alert.get(
                "severity",
                "MEDIUM"
            )

            risk_score = alert.get(
                "risk_score",
                0
            )

            username = alert.get(
                "username",
                "Unknown"
            )

            source_ip = alert.get(
                "source_ip",
                "Unknown"
            )

            attack_chain = build_attack_chain(
                alert
            )

            evidence = build_evidence(
                alert
            )

            priority = determine_priority(
                risk_score
            )

            confidence = determine_confidence(
                risk_score
            )

            mitre_techniques = get_mitre_mapping(
                attack_chain,
                threat_type,
                mitre_mapping
            )

            timeline = build_timeline(
                alert,
                attack_chain,
                risk_score
            )

            analyst_finding = build_analyst_finding(
                alert,
                attack_chain,
                mitre_techniques
            )

            recommended_actions = (
                build_recommended_actions(
                    attack_chain
                )
            )

            investigation = {

                "investigation_id":
                    f"INV-{index:04d}",

                "investigation_timestamp":
                    datetime.now().isoformat(),

                "alert_id":
                    alert.get(
                        "alert_id",
                        "UNKNOWN"
                    ),

                "threat_type":
                    threat_type,

                "severity":
                    severity,

                "risk_score":
                    risk_score,

                "priority":
                    priority,

                "confidence":
                    confidence,

                "affected_user":
                    username,

                "source_ip":
                    source_ip,

                "mitre_attack":
                    {
                        "techniques":
                            mitre_techniques
                    },

                "evidence":
                    evidence,

                "attack_chain":
                    attack_chain,

                "timeline":
                    timeline,

                "analyst_finding":
                    analyst_finding,

                "recommended_actions":
                    recommended_actions,

                "status":
                    "UNDER_INVESTIGATION"
            }

            investigations.append(
                investigation
            )

            # ====================================================
            # DISPLAY
            # ====================================================

            print()
            print("=" * 65)

            print(
                f"Investigation #{index}"
            )

            print(
                f"Threat: {threat_type}"
            )

            print(
                f"Severity: {severity}"
            )

            print(
                f"Risk Score: {risk_score}/100"
            )

            print(
                f"Priority: {priority}"
            )

            print(
                f"Confidence: {confidence}"
            )

            print(
                f"User: {username}"
            )

            print(
                f"Source IP: {source_ip}"
            )

            print()

            print(
                "MITRE ATT&CK Techniques:"
            )

            for technique in mitre_techniques:

                print(
                    f"  → {technique['technique_id']} - "
                    f"{technique['technique_name']} "
                    f"({technique['tactic']})"
                )

            print()

            print(
                "Attack Chain:"
            )

            for stage in attack_chain:

                print(
                    f"  → {stage}"
                )

            print()

            print(
                "Evidence:"
            )

            for item in evidence:

                print(
                    f"  - {item}"
                )

    # ============================================================
    # SAVE REPORT
    # ============================================================

    report = {

        "generated_at":
            datetime.now().isoformat(),

        "engine":
            "Investigation Engine V3.2",

        "mitre_attack_enabled":
            True,

        "total_alerts":
            len(alerts),

        "total_investigations":
            len(investigations),

        "investigations":
            investigations
    }

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

    print()
    print("=" * 65)

    print(
        f"Total investigations generated: "
        f"{len(investigations)}"
    )

    print(
        "Investigation report saved to:"
    )

    print(
        REPORT_FILE
    )

    print("=" * 65)


if __name__ == "__main__":

    main()