"""Policy-diff-driven authorization test selection for AuthTrace.

The planner is deterministic and does not contact a target. The runner executes only
mapped pytest node IDs and keeps reports free of tokens and response bodies.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_POLICY = Path("policy.json")
DEFAULT_POLICY_V2 = Path("policy.v2.json")
DEFAULT_MAPPING = Path("test_mapping.json")
DEFAULT_REPORT = Path("reports/latest_pipeline.json")
DEFAULT_DASHBOARD = Path("reports/dashboard.html")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def rule_index(policy):
    rules = policy.get("rules")
    if not isinstance(rules, list):
        raise SystemExit("Policy must contain a 'rules' array.")
    result = {}
    for rule in rules:
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise SystemExit("Every policy rule must have a non-empty string id.")
        if rule_id in result:
            raise SystemExit(f"Duplicate policy rule id: {rule_id}")
        result[rule_id] = rule
    return result


def diff_policies(old_policy, new_policy):
    old = rule_index(old_policy)
    new = rule_index(new_policy)
    changes = []
    for rule_id in sorted(set(old) | set(new)):
        if rule_id not in old:
            changes.append({"rule_id": rule_id, "change": "added", "before": None, "after": new[rule_id]})
        elif rule_id not in new:
            changes.append({"rule_id": rule_id, "change": "removed", "before": old[rule_id], "after": None})
        elif old[rule_id] != new[rule_id]:
            fields = sorted(k for k in set(old[rule_id]) | set(new[rule_id]) if old[rule_id].get(k) != new[rule_id].get(k))
            changes.append({"rule_id": rule_id, "change": "modified", "changed_fields": fields,
                            "before": old[rule_id], "after": new[rule_id]})
    return changes


def risk_score(change):
    """Transparent heuristic: policy changes that broaden access score highest."""
    before, after = change.get("before") or {}, change.get("after") or {}
    score = 1
    fields = set(change.get("changed_fields", []))
    if change["change"] == "removed":
        score += 4
    if change["change"] == "added":
        score += 2
    if "expected" in fields:
        if before.get("expected") == "deny" and after.get("expected") == "allow":
            score += 5
        else:
            score += 2
    if fields & {"condition", "actor", "action", "resource"}:
        score += 3
    if before.get("expected") == "allow" and after.get("expected") == "deny":
        score += 1
    return min(score, 10)


def build_plan(changes, mapping_doc):
    mapping = mapping_doc.get("mappings", [])
    by_rule = {}
    for item in mapping:
        for rule_id in item.get("policy_rule_ids", []):
            by_rule.setdefault(rule_id, []).append(item)
    planned = []
    unmapped = []
    for change in changes:
        rule_id = change["rule_id"]
        entries = by_rule.get(rule_id, [])
        score = risk_score(change)
        if not entries:
            unmapped.append(rule_id)
        for entry in entries:
            planned.append({
                "rule_id": rule_id,
                "change": change["change"],
                "risk_score": score,
                "risk": "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low",
                "test_nodeids": entry.get("test_nodeids", []),
                "test_area": entry.get("test_area", "authorization"),
                "rationale": entry.get("rationale", ""),
            })
    # De-duplicate test IDs while preserving risk priority.
    planned.sort(key=lambda item: (-item["risk_score"], item["rule_id"], item["test_area"]))
    selected = []
    for item in planned:
        for nodeid in item["test_nodeids"]:
            if nodeid not in selected:
                selected.append(nodeid)
    return {"selected_tests": selected, "items": planned, "unmapped_rules": sorted(unmapped)}


def safe_target(base_url):
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("Blocked: target must be an HTTP(S) URL with a hostname.")
    if parsed.username or parsed.password:
        raise SystemExit("Blocked: do not embed credentials in the target URL.")
    try:
        import ipaddress
        address = ipaddress.ip_address(parsed.hostname)
        loopback = address.is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    if not loopback and os.getenv("AUTHTRACE_ALLOW_STAGING") != "1":
        raise SystemExit("Blocked: non-loopback target. For explicitly authorized staging only, set AUTHTRACE_ALLOW_STAGING=1.")
    return parsed.geturl().rstrip("/")


def render_dashboard(report, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    checks = report.get("checks", [])
    rows = []
    for item in checks:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(item.get("rule_id", ""))),
                html.escape(str(item.get("risk", ""))),
                html.escape(", ".join(item.get("test_nodeids", []))),
                html.escape(str(item.get("verdict", ""))),
            )
        )
    overall = html.escape(str(report.get("overall", "UNKNOWN")))
    generated = html.escape(str(report.get("generated_at", "")))
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthTrace Policy Test Dashboard</title>
<style>
body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#17202a}
h1{margin-bottom:.25rem}.muted{color:#586575}.status{display:inline-block;padding:.3rem .6rem;border:1px solid #8795a1;border-radius:.35rem}
table{border-collapse:collapse;width:100%;margin-top:1.2rem}th,td{text-align:left;border-bottom:1px solid #d8dee4;padding:.7rem;overflow-wrap:anywhere}
th{background:#f4f6f8}.note{margin-top:1.5rem;padding:1rem;background:#f7f8fa}
</style></head><body>
<h1>AuthTrace Policy Test Dashboard</h1><p class="muted">Generated: """ + generated + """</p>
<p>Overall: <span class="status">""" + overall + """</span></p>
<p>Selected checks: """ + str(len(checks)) + """</p>
<table><thead><tr><th>Policy rule</th><th>Risk</th><th>Selected tests</th><th>Verdict</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table>
<div class="note"><strong>Scope:</strong> Results describe only the selected checks and declared policy changes. They are not proof that the entire API is secure.</div>
</body></html>"""
    output_path.write_text(document, encoding="utf-8")
    return output_path


def run_selected(plan, base_url):
    safe_target(base_url)
    if not plan["selected_tests"]:
        return [], 0
    env = os.environ.copy()
    env["AUTH_TRACE_BASE_URL"] = base_url
    results = []
    overall_rc = 0
    for nodeid in plan["selected_tests"]:
        started = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", nodeid],
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False,
        )
        duration = round(time.monotonic() - started, 3)
        # Console output is shown to the operator, but not persisted to the report.
        print(proc.stdout, end="" if proc.stdout.endswith("\\n") else "\\n")
        passed = proc.returncode == 0
        overall_rc = max(overall_rc, proc.returncode)
        results.append({
            "test_nodeids": [nodeid],
            "verdict": "PASS" if passed else "FAIL",
            "return_code": proc.returncode,
            "duration_seconds": duration,
            "response_bodies_recorded": False,
            "credentials_recorded": False,
        })
    return results, overall_rc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Diff policies, select risk-ranked tests, execute them, and create evidence.")
    parser.add_argument("--old-policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--new-policy", type=Path, default=DEFAULT_POLICY_V2)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dashboard", type=Path, default=DEFAULT_DASHBOARD)
    parser.add_argument("--base-url", default=os.getenv("AUTH_TRACE_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--execute", action="store_true", help="Execute only the selected pytest node IDs; requires a running authorized target.")
    parser.add_argument("--fail-on-unmapped", action="store_true", help="Return non-zero when changed rules have no test mapping.")
    args = parser.parse_args(argv)

    old_policy = load_json(args.old_policy)
    new_policy = load_json(args.new_policy)
    mapping_doc = load_json(args.mapping)
    changes = diff_policies(old_policy, new_policy)
    plan = build_plan(changes, mapping_doc)

    checks = []
    return_code = 0
    if args.execute:
        checks, return_code = run_selected(plan, args.base_url)
    if args.fail_on_unmapped and plan["unmapped_rules"]:
        return_code = max(return_code, 2)

    report = {
        "tool": "AuthTrace policy pipeline",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_versions": {
            "old": old_policy.get("policy_version", "unknown"),
            "new": new_policy.get("policy_version", "unknown"),
        },
        "summary": {
            "changed_rules": len(changes),
            "selected_tests": len(plan["selected_tests"]),
            "unmapped_rules": len(plan["unmapped_rules"]),
        },
        "changes": [{"rule_id": c["rule_id"], "change": c["change"],
                     "changed_fields": c.get("changed_fields", []), "risk_score": risk_score(c)}
                    for c in changes],
        "plan": plan,
        "checks": checks,
        "overall": ("FAIL" if return_code else "PASS") if args.execute else
                   ("NEEDS_MAPPING" if plan["unmapped_rules"] else "PLANNED"),
        "limitations": [
            "Risk scores are a transparent heuristic, not a calibrated probability.",
            "A planned run is not evidence that tests executed.",
            "Results cover only selected tests and do not prove the whole API is secure.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    render_dashboard(report, args.dashboard)
    print(json.dumps({"summary": report["summary"], "overall": report["overall"],
                      "selected_tests": plan["selected_tests"], "unmapped_rules": plan["unmapped_rules"],
                      "report": str(args.report), "dashboard": str(args.dashboard)}, indent=2))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
