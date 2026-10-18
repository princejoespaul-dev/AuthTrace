
import json
from pathlib import Path

import streamlit as st

REPORT_PATH = Path("reports/explained_latest.json")

st.set_page_config(
    page_title="AuthTrace Explainer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AuthTrace Explainer")
st.caption("Authorization test results and evidence-based explanations")

if not REPORT_PATH.exists():
    st.error(f"Report not found: {REPORT_PATH}")
    st.info(
        "Run AuthTrace and the explainer first, then refresh this page."
    )
    st.stop()

try:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    st.error(f"Could not read the report: {exc}")
    st.stop()

checks = report.get("checks", [])
summary = report.get("summary", {})
counts = summary.get("verdict_counts", {})

if not isinstance(checks, list) or not isinstance(summary, dict):
    st.error("The report structure is invalid.")
    st.stop()

overall = report.get("overall", "UNKNOWN")
st.subheader(f"Overall result: {overall}")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total checks", summary.get("total_checks", len(checks)))
col2.metric("Passed", counts.get("PASS", 0))
col3.metric("Failed", counts.get("FAIL", 0))
col4.metric("Errors", counts.get("ERROR", 0))

st.caption(
    f"Target mode: {report.get('target_mode', 'unknown')} · "
    f"Generated: {report.get('generated_at', 'unknown')}"
)

st.divider()
st.subheader("Test results")

for index, check in enumerate(checks):
    if not isinstance(check, dict):
        continue

    verdict = str(check.get("verdict", "INCONCLUSIVE")).upper()
    test_id = check.get("test_id", f"Check {index + 1}")
    explanation = check.get("explanation", {})

    with st.expander(f"{verdict} — {test_id}", expanded=(verdict == "FAIL")):
        left, right = st.columns(2)

        with left:
            st.write("**Policy:**", check.get("policy_id", "Unknown"))
            st.write("**Action:**", check.get("action", "Unknown"))
            st.write("**Expected:**", check.get("expected", "Unknown"))
            st.write("**Observed:**", check.get("observed", "Unknown"))
            st.write("**HTTP status:**", check.get("http_status", "Unknown"))

        with right:
            st.write("**Explanation**")
            st.write(explanation.get("summary", "No explanation available."))

            st.write("**Likely cause**")
            st.write(explanation.get("likely_cause", "Not determined."))

        st.write("**Recommended fix**")
        st.write(explanation.get("recommended_fix", "None provided."))

        st.write("**Verification steps**")
        for step in explanation.get("verification_steps", []):
            st.write(f"- {step}")

        st.write("**Evidence**")
        for item in explanation.get("evidence", []):
            st.code(str(item))

        st.write("**Limitations**")
        for item in explanation.get("limitations", []):
            st.write(f"- {item}")

        ai_suggestion = explanation.get("ai_wording_suggestion")
        if isinstance(ai_suggestion, dict):
            with st.expander("Optional AI wording suggestions"):
                st.warning(
                    "AI-generated content is unverified; "
                    "the rule-based explanation remains authoritative."
                )
                st.write(ai_suggestion.get("summary", ""))
                st.write("**Suggested fix**")
                st.write(ai_suggestion.get("recommended_fix", ""))

st.divider()
st.caption(
    "AuthTrace verdicts are preserved. Explanations are advisory "
    "and do not independently prove a vulnerability."
)