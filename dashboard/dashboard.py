import streamlit as st
import json
import os
import pandas as pd


# ============================================================
# AI-ASSISTED SOC PLATFORM
# DASHBOARD V4.1
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "reports"
)


# ============================================================
# FILE PATHS
# ============================================================

SECURITY_EVENTS_FILE = os.path.join(
    DATA_DIR,
    "test_v7_security_events.json"
)

ALERTS_FILE = os.path.join(
    DATA_DIR,
    "alerts.json"
)

INVESTIGATION_FILE = os.path.join(
    REPORT_DIR,
    "investigation_report_v3.json"
)

RESPONSE_FILE = os.path.join(
    REPORT_DIR,
    "response_report_v2.json"
)

AI_TRIAGE_FILE = os.path.join(
    REPORT_DIR,
    "ai_triage_report.json"
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI-Assisted SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# LOAD JSON
# ============================================================

def load_json(file_path, default):

    if not os.path.exists(file_path):
        return default

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception:

        return default


# ============================================================
# NORMALIZE JSON DATA
# ============================================================

def normalize_list(data):

    # Already a list
    if isinstance(data, list):
        return [
            item
            for item in data
            if isinstance(item, dict)
        ]

    # Dictionary
    if isinstance(data, dict):

        # Common wrapper names
        for key in [
            "alerts",
            "investigations",
            "responses",
            "results",
            "response_results",
            "investigation_results",
            "triage_results",
            "ai_triage"
        ]:

            if key in data:

                value = data[key]

                if isinstance(value, list):

                    return [
                        item
                        for item in value
                        if isinstance(item, dict)
                    ]

                if isinstance(value, dict):

                    return [value]

        # Single dictionary record
        return [data]

    # Anything else
    return []


# ============================================================
# LOAD ALL DATA
# ============================================================

security_events = load_json(
    SECURITY_EVENTS_FILE,
    []
)

alerts = load_json(
    ALERTS_FILE,
    []
)

investigations = load_json(
    INVESTIGATION_FILE,
    []
)

responses = load_json(
    RESPONSE_FILE,
    []
)

ai_triage = load_json(
    AI_TRIAGE_FILE,
    []
)


# ============================================================
# NORMALIZE ALL DATA
# ============================================================

security_events = normalize_list(
    security_events
)

alerts = normalize_list(
    alerts
)

investigations = normalize_list(
    investigations
)

responses = normalize_list(
    responses
)

ai_triage = normalize_list(
    ai_triage
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title(
    "🛡️ SOC Platform"
)

st.sidebar.markdown(
    "### Engine Versions"
)

st.sidebar.write(
    "Collector: V1"
)

st.sidebar.write(
    "Detection: V7"
)

st.sidebar.write(
    "Investigation: V3.2"
)

st.sidebar.write(
    "Response: V2"
)

st.sidebar.write(
    "AI Triage: V1"
)

st.sidebar.write(
    "Dashboard: V4.1"
)

st.sidebar.markdown("---")


if st.sidebar.button(
    "🔄 Refresh Dashboard"
):

    st.rerun()


st.sidebar.markdown("---")

st.sidebar.info(
    "Current dataset contains simulated "
    "security events for safe SOC testing."
)


# ============================================================
# TITLE
# ============================================================

st.title(
    "🛡️ AI-Assisted SOC Dashboard"
)

st.caption(
    "Security Operations Center — "
    "Detection, Investigation, Response "
    "and AI-Assisted Alert Triage"
)


# ============================================================
# SECURITY STATUS
# ============================================================

critical_alerts = sum(
    1
    for alert in alerts
    if alert.get(
        "severity"
    ) == "CRITICAL"
)

high_alerts = sum(
    1
    for alert in alerts
    if alert.get(
        "severity"
    ) == "HIGH"
)


if critical_alerts > 0:

    st.error(
        "🚨 CRITICAL SECURITY ACTIVITY DETECTED"
    )

elif high_alerts > 0:

    st.warning(
        "⚠️ HIGH-RISK SECURITY ACTIVITY DETECTED"
    )

elif alerts:

    st.warning(
        "⚠️ SECURITY ALERTS DETECTED"
    )

else:

    st.success(
        "✅ SYSTEM STATUS: NORMAL"
    )


# ============================================================
# TOP METRICS
# ============================================================

col1, col2, col3, col4, col5, col6 = st.columns(6)


col1.metric(
    "Total Events",
    len(security_events)
)

col2.metric(
    "Total Alerts",
    len(alerts)
)

col3.metric(
    "Critical Alerts",
    critical_alerts
)

col4.metric(
    "Investigations",
    len(investigations)
)

col5.metric(
    "Responses",
    len(responses)
)

col6.metric(
    "AI Triaged",
    len(ai_triage)
)


st.markdown("---")


# ============================================================
# AI TRIAGE CENTER
# ============================================================

st.header(
    "🤖 AI-Assisted Alert Triage"
)


if ai_triage:

    for index, triage in enumerate(
        ai_triage,
        start=1
    ):

        st.subheader(
            f"Triage #{index}"
        )

        classification = triage.get(
            "classification",
            "UNKNOWN"
        )

        confidence = triage.get(
            "confidence",
            "UNKNOWN"
        )

        priority = triage.get(
            "priority",
            "UNKNOWN"
        )

        risk_score = triage.get(
            "risk_score",
            0
        )

        severity = triage.get(
            "severity",
            "UNKNOWN"
        )

        username = triage.get(
            "username",
            "Unknown"
        )

        source_ip = triage.get(
            "source_ip",
            "Unknown"
        )


        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        if classification == "TRUE POSITIVE":

            st.error(
                f"🚨 AI Classification: "
                f"{classification}"
            )

        elif classification == "NEEDS REVIEW":

            st.warning(
                f"⚠️ AI Classification: "
                f"{classification}"
            )

        else:

            st.success(
                f"✅ AI Classification: "
                f"{classification}"
            )


        metric1, metric2, metric3, metric4 = st.columns(4)


        metric1.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

        metric2.metric(
            "Confidence",
            confidence
        )

        metric3.metric(
            "Priority",
            priority
        )

        metric4.metric(
            "Severity",
            severity
        )


        st.write(
            f"**Affected User:** `{username}`"
        )

        st.write(
            f"**Source IP:** `{source_ip}`"
        )


        # ----------------------------------------------------
        # AI Explanation
        # ----------------------------------------------------

        st.subheader(
            "🧠 AI Analyst Explanation"
        )

        st.info(
            triage.get(
                "ai_explanation",
                "No explanation available."
            )
        )


        # ----------------------------------------------------
        # Attack Chain
        # ----------------------------------------------------

        st.subheader(
            "🔗 Attack Chain"
        )

        attack_chain = triage.get(
            "attack_chain",
            []
        )

        if isinstance(
            attack_chain,
            list
        ):

            st.write(
                " → ".join(
                    str(item)
                    for item in attack_chain
                )
            )

        else:

            st.write(
                str(attack_chain)
            )


        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        st.subheader(
            "🔎 Evidence"
        )

        evidence = triage.get(
            "evidence",
            []
        )

        if isinstance(
            evidence,
            list
        ):

            for item in evidence:

                st.write(
                    f"• {item}"
                )

        else:

            st.write(
                str(evidence)
            )


        # ----------------------------------------------------
        # Recommended Actions
        # ----------------------------------------------------

        st.subheader(
            "🎯 Recommended Analyst Actions"
        )

        actions = triage.get(
            "recommended_actions",
            []
        )

        if isinstance(
            actions,
            list
        ):

            for action_number, action in enumerate(
                actions,
                start=1
            ):

                st.write(
                    f"{action_number}. {action}"
                )

        else:

            st.write(
                str(actions)
            )


        st.markdown("---")


else:

    st.info(
        "No AI triage results available."
    )


# ============================================================
# EVENT SUMMARY
# ============================================================

st.header(
    "📊 Security Event Summary"
)


if security_events:

    event_ids = []

    for event in security_events:

        event_ids.append(
            event.get(
                "event_id",
                "Unknown"
            )
        )


    summary = {}

    for event_id in event_ids:

        summary[event_id] = (
            summary.get(
                event_id,
                0
            ) + 1
        )


    summary_df = pd.DataFrame(
        {
            "Event ID": list(
                summary.keys()
            ),
            "Count": list(
                summary.values()
            )
        }
    )


    st.dataframe(
        summary_df,
        use_container_width=True,
        hide_index=True
    )


else:

    st.info(
        "No security events available."
    )


# ============================================================
# RISK OVERVIEW
# ============================================================

st.header(
    "⚠️ Risk Overview"
)


if alerts:

    risk_values = []

    for alert in alerts:

        risk_values.append(
            alert.get(
                "risk_score",
                0
            )
        )


    if risk_values:

        max_risk = max(
            risk_values
        )

    else:

        max_risk = 0


    st.metric(
        "Highest Risk Score",
        f"{max_risk}/100"
    )

else:

    st.metric(
        "Highest Risk Score",
        "0/100"
    )


# ============================================================
# SECURITY ALERTS
# ============================================================

st.header(
    "🚨 Security Alerts"
)


if alerts:

    for index, alert in enumerate(
        alerts,
        start=1
    ):

        threat_type = alert.get(
            "threat_type",
            "Unknown Threat"
        )


        with st.expander(
            f"Alert #{index} — "
            f"{threat_type}"
        ):

            st.write(
                "**Severity:**",
                alert.get(
                    "severity",
                    "Unknown"
                )
            )

            st.write(
                "**Risk Score:**",
                alert.get(
                    "risk_score",
                    0
                )
            )

            st.write(
                "**User:**",
                alert.get(
                    "username",
                    "Unknown"
                )
            )

            st.write(
                "**Source IP:**",
                alert.get(
                    "source_ip",
                    "Unknown"
                )
            )

            st.write(
                "**Status:**",
                alert.get(
                    "status",
                    "Unknown"
                )
            )


            st.subheader(
                "Attack Chain"
            )

            attack_chain = alert.get(
                "attack_chain",
                []
            )

            if isinstance(
                attack_chain,
                list
            ):

                st.write(
                    " → ".join(
                        str(item)
                        for item in attack_chain
                    )
                )


            st.subheader(
                "Evidence"
            )

            evidence_items = alert.get(
                "evidence",
                []
            )

            if isinstance(
                evidence_items,
                list
            ):

                for evidence_item in evidence_items:

                    st.write(
                        f"• {evidence_item}"
                    )

else:

    st.info(
        "No security alerts detected."
    )


# ============================================================
# MITRE ATT&CK
# ============================================================
# ============================================================
# MITRE ATT&CK
# ============================================================

st.header("🎯 MITRE ATT&CK Analysis")

if investigations:

    for index, investigation in enumerate(
        investigations,
        start=1
    ):

        if not isinstance(investigation, dict):
            continue

        st.subheader(
            f"Investigation #{index}"
        )

        # ----------------------------------------------------
        # GET MITRE DATA
        # ----------------------------------------------------

        techniques = (
            investigation.get("mitre_attack")
            or investigation.get("mitre_techniques")
            or investigation.get("mitre")
            or []
        )

        # Sometimes MITRE information may be inside
        # an investigation_details object
        if not techniques:

            details = investigation.get(
                "investigation",
                {}
            )

            if isinstance(details, dict):

                techniques = (
                    details.get("mitre_attack")
                    or details.get("mitre_techniques")
                    or details.get("mitre")
                    or []
                )

        # ----------------------------------------------------
        # NORMALIZE MITRE DATA
        # ----------------------------------------------------

        if isinstance(techniques, dict):

            techniques = [
                techniques
            ]

        elif isinstance(techniques, str):

            techniques = [
                techniques
            ]

        # ----------------------------------------------------
        # DISPLAY
        # ----------------------------------------------------

        if techniques:

            for technique in techniques:

                # --------------------------------------------
                # Dictionary format
                # --------------------------------------------

                if isinstance(
                    technique,
                    dict
                ):

                    technique_id = (
                        technique.get("technique_id")
                        or technique.get("id")
                        or technique.get("attack_id")
                        or "Unknown"
                    )

                    technique_name = (
                        technique.get("technique_name")
                        or technique.get("name")
                        or technique.get("technique")
                        or "Unknown"
                    )

                    tactic = (
                        technique.get("tactic")
                        or technique.get("tactics")
                        or "Unknown"
                    )

                    st.write(
                        f"• **{technique_id}** — "
                        f"{technique_name} "
                        f"({tactic})"
                    )

                # --------------------------------------------
                # String format
                # --------------------------------------------

                elif isinstance(
                    technique,
                    str
                ):

                    st.write(
                        f"• {technique}"
                    )

        else:

            st.warning(
                "No MITRE ATT&CK techniques found "
                "for this investigation."
            )

else:

    st.info(
        "No investigation results available."
    )
# ============================================================
# INVESTIGATION CENTER
# ============================================================

# ============================================================
# INVESTIGATION CENTER
# ============================================================

st.header("🔍 Investigation Center")

if investigations:

    for index, investigation in enumerate(
        investigations,
        start=1
    ):

        if not isinstance(
            investigation,
            dict
        ):
            continue

        # Handle nested investigation object
        details = investigation.get(
            "investigation",
            investigation
        )

        if not isinstance(
            details,
            dict
        ):
            details = investigation

        with st.expander(
            f"Investigation #{index}",
            expanded=True
        ):

            st.write(
                "**Threat:**",
                details.get(
                    "threat_type",
                    "Unknown"
                )
            )

            st.write(
                "**Severity:**",
                details.get(
                    "severity",
                    "Unknown"
                )
            )

            st.write(
                "**Risk Score:**",
                details.get(
                    "risk_score",
                    0
                )
            )

            st.write(
                "**Priority:**",
                details.get(
                    "priority",
                    "Unknown"
                )
            )

            st.write(
                "**Confidence:**",
                details.get(
                    "confidence",
                    "Unknown"
                )
            )

            st.write(
                "**User:**",
                details.get(
                    "username",
                    details.get(
                        "affected_user",
                        "Unknown"
                    )
                )
            )

            st.write(
                "**Source IP:**",
                details.get(
                    "source_ip",
                    "Unknown"
                )
            )

            # ------------------------------------------------
            # ATTACK CHAIN
            # ------------------------------------------------

            st.subheader(
                "🔗 Attack Chain"
            )

            attack_chain = details.get(
                "attack_chain",
                []
            )

            if isinstance(
                attack_chain,
                list
            ):

                for step in attack_chain:

                    st.write(
                        f"→ {step}"
                    )

            else:

                st.write(
                    str(attack_chain)
                )

            # ------------------------------------------------
            # EVIDENCE
            # ------------------------------------------------

            st.subheader(
                "🔎 Evidence"
            )

            evidence = details.get(
                "evidence",
                []
            )

            if isinstance(
                evidence,
                list
            ):

                for item in evidence:

                    st.write(
                        f"• {item}"
                    )

            else:

                st.write(
                    str(evidence)
                )

            # ------------------------------------------------
            # ANALYST FINDING
            # ------------------------------------------------

            st.subheader(
                "🧠 Analyst Finding"
            )

            finding = (
                details.get(
                    "analyst_finding"
                )
                or details.get(
                    "finding"
                )
                or "No analyst finding available."
            )

            st.info(
                finding
            )

            # ------------------------------------------------
            # ACTIONS
            # ------------------------------------------------

            st.subheader(
                "🎯 Recommended Actions"
            )

            recommended_actions = details.get(
                "recommended_actions",
                []
            )

            if isinstance(
                recommended_actions,
                list
            ):

                for action_number, action in enumerate(
                    recommended_actions,
                    start=1
                ):

                    if isinstance(
                        action,
                        dict
                    ):

                        action_text = action.get(
                            "action",
                            str(action)
                        )

                        st.write(
                            f"{action_number}. {action_text}"
                        )

                    else:

                        st.write(
                            f"{action_number}. {action}"
                        )

else:

    st.info(
        "No investigation records available."
    )
# ============================================================
# RESPONSE CENTER
# ============================================================
# ============================================================
# RESPONSE CENTER
# ============================================================

st.header("🛠️ Response Center")

if responses:

    for index, response in enumerate(
        responses,
        start=1
    ):

        if not isinstance(
            response,
            dict
        ):
            continue

        threat = (
            response.get("threat_type")
            or response.get("threat")
            or "Unknown Threat"
        )

        with st.expander(
            f"Response #{index} — {threat}"
        ):

            st.write(
                "**Threat:**",
                threat
            )

            st.write(
                "**Severity:**",
                response.get(
                    "severity",
                    "Unknown"
                )
            )

            st.write(
                "**Risk Score:**",
                response.get(
                    "risk_score",
                    0
                )
            )

            st.write(
                "**Response Level:**",
                response.get(
                    "response_level",
                    "Unknown"
                )
            )

            st.write(
                "**Status:**",
                response.get(
                    "status",
                    "Unknown"
                )
            )

            st.subheader(
                "🎯 Recommended Response Actions"
            )

            actions = response.get(
                "recommended_actions",
                []
            )

            if isinstance(actions, list):

                for action_number, action in enumerate(
                    actions,
                    start=1
                ):

                    # ----------------------------------------
                    # Dictionary action
                    # ----------------------------------------

                    if isinstance(
                        action,
                        dict
                    ):

                        action_text = (
                            action.get(
                                "action",
                                "Unknown action"
                            )
                        )

                        reason = (
                            action.get(
                                "reason",
                                ""
                            )
                        )

                        priority = (
                            action.get(
                                "priority",
                                action_number
                            )
                        )

                        st.write(
                            f"**{priority}. {action_text}**"
                        )

                        if reason:

                            st.caption(
                                f"Reason: {reason}"
                            )

                    # ----------------------------------------
                    # String action
                    # ----------------------------------------

                    else:

                        st.write(
                            f"**{action_number}. {action}**"
                        )

            elif isinstance(
                actions,
                dict
            ):

                action_text = actions.get(
                    "action",
                    "Unknown action"
                )

                reason = actions.get(
                    "reason",
                    ""
                )

                st.write(
                    f"**1. {action_text}**"
                )

                if reason:

                    st.caption(
                        f"Reason: {reason}"
                    )

            else:

                st.info(
                    "No response actions available."
                )

else:

    st.info(
        "No response records available."
    )
# ============================================================
# RAW DATA
# ============================================================

st.header(
    "📄 Raw Security Data"
)


tab1, tab2, tab3, tab4, tab5 = st.tabs(
    [
        "Security Events",
        "Alerts",
        "AI Triage",
        "Investigation",
        "Response"
    ]
)


with tab1:

    st.json(
        security_events
    )


with tab2:

    st.json(
        alerts
    )


with tab3:

    st.json(
        ai_triage
    )


with tab4:

    st.json(
        investigations
    )


with tab5:

    st.json(
        responses
    )


# ============================================================
# FILE STATUS
# ============================================================

st.header(
    "📁 System File Status"
)


files_to_check = {

    "Security Events":
        SECURITY_EVENTS_FILE,

    "Alerts":
        ALERTS_FILE,

    "Investigation":
        INVESTIGATION_FILE,

    "Response":
        RESPONSE_FILE,

    "AI Triage":
        AI_TRIAGE_FILE
}


for name, path in files_to_check.items():

    if os.path.exists(path):

        st.success(
            f"✅ {name}: Available"
        )

    else:

        st.warning(
            f"⚠️ {name}: Not found"
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "AI-Assisted SOC Platform | "
    "Detection V7 | "
    "Investigation V3.2 | "
    "Response V2 | "
    "AI Triage V1 | "
    "Dashboard V4.1"
)