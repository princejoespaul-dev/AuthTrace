"""Deterministic policy-diff-driven authorization test selection for AuthTrace."""
from __future__ import annotations

import argparse
import html
import hashlib
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
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc
    return value


def validate_policy(policy):
    """Validate the supported AuthTrace policy schema before planning or execution."""
    if not isinstance(policy, dict) or not policy:
        raise SystemExit("Policy must be a non-empty JSON object.")
    allowed_top = {"policy_version", "description", "rules", "scope"}
    extra = sorted(set(policy) - allowed_top)
    if extra:
        raise SystemExit("Unsupported policy field(s): " + ", ".join(extra))
    if not isinstance(policy.get("policy_version"), str) or not policy["policy_version"].strip():
        raise SystemExit("Policy requires a non-empty string 'policy_version'.")
    if "description" in policy and not isinstance(policy["description"], str):
        raise SystemExit("Policy 'description' must be a string.")
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SystemExit("Policy must contain a non-empty 'rules' array.")
    allowed_rule = {"id", "actor", "action", "resource", "condition", "expected"}
    valid_actors = {"user", "admin"}
    valid_actions = {"read_invoice"}
    valid_resources = {"invoice"}
    valid_conditions = {
        "invoice.owner_id == actor.user_id",
        "invoice.owner_id != actor.user_id",
        "actor.role == admin",
    }
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise SystemExit(f"Policy rule at index {i} must be an object.")
        extra_fields = sorted(set(rule) - allowed_rule)
        if extra_fields:
            raise SystemExit(f"Rule at index {i}: unsupported field(s): " + ", ".join(extra_fields))
        for field in ("id", "actor", "action", "resource", "condition", "expected"):
            if field not in rule:
                raise SystemExit(f"Rule at index {i}: missing required field '{field}'.")
        if not isinstance(rule["id"], str) or not rule["id"].strip():
            raise SystemExit(f"Rule at index {i}: 'id' must be a non-empty string.")
        if not isinstance(rule["actor"], str) or rule["actor"] not in valid_actors:
            raise SystemExit(f"Rule {rule['id']}: actor must be one of {sorted(valid_actors)}.")
        if not isinstance(rule["action"], str) or rule["action"] not in valid_actions:
            raise SystemExit(f"Rule {rule['id']}: action must be one of {sorted(valid_actions)}.")
        if not isinstance(rule["resource"], str) or rule["resource"] not in valid_resources:
            raise SystemExit(f"Rule {rule['id']}: resource must be one of {sorted(valid_resources)}.")
        if not isinstance(rule["condition"], str) or rule["condition"] not in valid_conditions:
            raise SystemExit(f"Rule {rule['id']}: unsupported condition.")
        if not isinstance(rule["expected"], str) or rule["expected"] not in {"allow", "deny"}:
            raise SystemExit(f"Rule {rule['id']}: expected must be 'allow' or 'deny'.")
    rule_index(policy)
    scope = policy.get("scope")
    if not isinstance(scope, dict):
        raise SystemExit("Policy requires a 'scope' object.")
    if set(scope) - {"base_url", "allowed_hosts", "default_methods"}:
        raise SystemExit("Policy scope contains unsupported fields.")
    if scope.get("base_url") != "http://127.0.0.1:8000":
        raise SystemExit("Policy scope base_url must be http://127.0.0.1:8000.")
    if scope.get("allowed_hosts") != ["127.0.0.1", "localhost"]:
        raise SystemExit("Policy scope allowed_hosts must be ['127.0.0.1', 'localhost'].")
    if scope.get("default_methods") != ["GET"]:
        raise SystemExit("Policy scope default_methods must be ['GET'].")
    return policy


def rule_index(policy):
    if not isinstance(policy, dict):
        raise SystemExit("Policy must be a JSON object.")
    rules = policy.get("rules")
    if not isinstance(rules, list):
        raise SystemExit("Policy must contain a 'rules' array.")
    result = {}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise SystemExit(f"Policy rule at index {index} must be an object.")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise SystemExit(f"Policy rule at index {index} must have a non-empty string id.")
        if rule_id in result:
            raise SystemExit(f"Duplicate policy rule id: {rule_id}")
        for field in ("actor", "action", "resource", "condition"):
            value = rule.get(field)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise SystemExit(f"Rule {rule_id}: {field} must be a non-empty string when provided.")
        expected = rule.get("expected")
        if expected is not None and (
            not isinstance(expected, str) or expected not in {"allow", "deny"}
        ):
            raise SystemExit(f"Rule {rule_id}: expected must be 'allow' or 'deny'.")
        result[rule_id] = rule
    return result


def validate_mapping(mapping_doc):
    if not isinstance(mapping_doc, dict):
        raise SystemExit("Test mapping must be a JSON object.")
    mappings = mapping_doc.get("mappings")
    if not isinstance(mappings, list):
        raise SystemExit("Test mapping must contain a 'mappings' array.")
    seen_pairs = set()
    for index, entry in enumerate(mappings):
        if not isinstance(entry, dict):
            raise SystemExit(f"Mapping at index {index} must be an object.")
        rule_ids = entry.get("policy_rule_ids")
        nodeids = entry.get("test_nodeids")
        if not isinstance(rule_ids, list) or not rule_ids:
            raise SystemExit(f"Mapping at index {index} must have non-empty policy_rule_ids.")
        if any(not isinstance(x, str) or not x.strip() for x in rule_ids):
            raise SystemExit(f"Mapping at index {index} contains an invalid policy rule ID.")
        if not isinstance(nodeids, list) or not nodeids:
            raise SystemExit(f"Mapping at index {index} must have non-empty test_nodeids.")
        if any(not isinstance(x, str) or not x.strip() or "::" not in x for x in nodeids):
            raise SystemExit(f"Mapping at index {index} contains an invalid pytest node ID.")
        for rule_id in rule_ids:
            pair = (rule_id, tuple(nodeids))
            if pair in seen_pairs:
                raise SystemExit(f"Duplicate mapping for policy rule {rule_id}.")
            seen_pairs.add(pair)
    return mappings


def validate_mapping_rule_ids(mapping_doc, known_rule_ids):
    """Reject mappings that refer to policy rules absent from both policy versions."""
    known = set(known_rule_ids)
    unknown = sorted({
        rule_id
        for entry in validate_mapping(mapping_doc)
        for rule_id in entry["policy_rule_ids"]
        if rule_id not in known
    })
    if unknown:
        raise SystemExit("Test mapping references unknown policy rule ID(s): " + ", ".join(unknown))


def validate_nodeid_paths(mapping_doc, root=Path.cwd()):
    """Ensure mapped test files exist and stay inside the repository root."""
    missing = []
    root = root.resolve()
    for entry in validate_mapping(mapping_doc):
        for nodeid in entry["test_nodeids"]:
            test_path = nodeid.split("::", 1)[0]
            candidate = (root / test_path).resolve()
            if not candidate.is_relative_to(root) or not candidate.is_file():
                missing.append(nodeid)
    return sorted(set(missing))


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
            fields = sorted(k for k in set(old[rule_id]) | set(new[rule_id])
                            if old[rule_id].get(k) != new[rule_id].get(k))
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
            score += 6
        else:
            score += 2
    if fields & {"condition", "actor", "action", "resource"}:
        score += 3
    if before.get("expected") == "allow" and after.get("expected") == "deny":
        score += 1
    return min(score, 10)


def risk_explanation(change):
    before, after = change.get("before") or {}, change.get("after") or {}
    if before.get("expected") == "deny" and after.get("expected") == "allow":
        return "Deny-to-allow broadens declared access and is prioritized as a high-risk authorization change."
    if change["change"] == "removed":
        return "Removing a policy rule can remove an explicit authorization control."
    if change["change"] == "added":
        return "A new rule changes the policy surface and requires review."
    if before.get("expected") == "allow" and after.get("expected") == "deny":
        return "Allow-to-deny narrows declared access; verify legitimate access remains available."
    if set(change.get("changed_fields", [])) & {"condition", "actor", "action", "resource"}:
        return "A change to the actor, action, resource, or condition can alter authorization scope."
    return "Policy rule changed; review the changed fields and mapped tests."


def build_plan(changes, mapping_doc):
    mapping = validate_mapping(mapping_doc)
    by_rule = {}
    for item in mapping:
        for rule_id in item["policy_rule_ids"]:
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
                "rule_id": rule_id, "change": change["change"], "risk_score": score,
                "risk": "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low",
                "risk_explanation": risk_explanation(change),
                "test_nodeids": entry["test_nodeids"],
                "test_area": entry.get("test_area", "authorization"),
                "rationale": entry.get("rationale", ""),
            })
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
    if parsed.query or parsed.fragment:
        raise SystemExit("Blocked: target URL must not contain a query string or fragment.")
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
    checks = report.get("checks", []) or [dict(item, verdict="PLANNED")
                                           for item in report.get("plan", {}).get("items", [])]
    rows = []
    for item in checks:
        nodeids = item.get("test_nodeids", [])
        if not isinstance(nodeids, list):
            nodeids = []
        rows.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(item.get("rule_id", ""))),
            html.escape(str(item.get("risk", ""))),
            html.escape(", ".join(str(x) for x in nodeids)),
            html.escape(str(item.get("verdict", ""))),
        ))
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
<div class="note"><strong>Scope:</strong> Results describe only selected checks and declared policy changes. They are not proof that the entire API is secure.</div>
</body></html>"""
    output_path.write_text(document, encoding="utf-8")
    return output_path


def run_selected(plan, base_url, expected_outcomes=None, timeout_seconds=30):
    """Run only validated selected pytest node IDs and retain sanitized evidence."""
    safe_target(base_url)
    if not plan["selected_tests"]:
        return [], 2, "ERROR"
    env = os.environ.copy()
    env["AUTH_TRACE_BASE_URL"] = base_url
    env["AUTH_TRACE_EXPECTED_OUTCOMES"] = json.dumps(expected_outcomes or {})
    results, overall_rc, statuses = [], 0, []
    for nodeid in plan["selected_tests"]:
        started = time.monotonic()
        evidence = None
        output = ""
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-s", nodeid],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False, timeout=timeout_seconds, shell=False,
            )
            output = proc.stdout or ""
            duration = round(time.monotonic() - started, 3)
            for line in output.splitlines():
                if line.startswith("AUTHTRACE_EVIDENCE="):
                    try:
                        evidence = json.loads(line.split("=", 1)[1])
                    except json.JSONDecodeError:
                        evidence = {"error": "Malformed structured test evidence"}
            lower = output.lower()
            collection_error = any(x in lower for x in (
                "error collecting", "no tests ran", "not found:", "importerror", "modulenotfounderror",
            ))
            if collection_error or proc.returncode not in (0, 1):
                status, error_class = "ERROR", "COLLECTION_OR_RUNNER_ERROR"
            elif proc.returncode == 0:
                status, error_class = "PASS", None
            elif evidence and evidence.get("classification") == "SECURITY_REGRESSION":
                status, error_class = "SECURITY_REGRESSION", "AUTHORIZATION_INVARIANT_VIOLATION"
            elif evidence and evidence.get("classification") == "POLICY_MISMATCH":
                status, error_class = "POLICY_MISMATCH", "OBSERVED_BEHAVIOR_DIFFERS_FROM_POLICY"
            else:
                status, error_class = "FAIL", "ASSERTION_FAILURE"
            rc = proc.returncode
            # Keep diagnostics bounded and omit headers/tokens and arbitrary response bodies.
            safe_output = "\n".join(line for line in output.splitlines()
                if not any(secret in line.lower() for secret in ("authorization:", "bearer ", "token-user-")))
            failure_lines = [line.strip() for line in safe_output.splitlines()
                             if "assert" in line.lower() or "error" in line.lower() or "failed" in line.lower()]
            failure = " | ".join(failure_lines[-4:])[:1200] or None
        except subprocess.TimeoutExpired:
            duration, status, rc, error_class = round(time.monotonic() - started, 3), "TIMEOUT", 124, "TEST_TIMEOUT"
            failure = "Selected test exceeded the execution timeout."
        except OSError as exc:
            duration, status, rc, error_class = round(time.monotonic() - started, 3), "ERROR", 2, "RUNNER_START_ERROR"
            failure = f"Could not start pytest ({type(exc).__name__})."
        statuses.append(status)
        overall_rc = max(overall_rc, rc if rc else (2 if status in {"ERROR", "TIMEOUT"} else 0))
        print(f"{nodeid}: {status} ({duration:.3f}s)")
        associated = [item for item in plan.get("items", []) if nodeid in item.get("test_nodeids", [])]
        results.append({
            "test_nodeids": [nodeid], "rule_ids": sorted({item["rule_id"] for item in associated}),
            "expected_outcomes": {item["rule_id"]: (expected_outcomes or {}).get(item["rule_id"])
                                  for item in associated},
            "verdict": status, "return_code": rc,
            "duration_seconds": duration, "error_class": error_class,
            "evidence": evidence, "failure_details": failure,
            "response_bodies_recorded": False, "credentials_recorded": False,
        })
    overall = ("ERROR" if "ERROR" in statuses else "TIMEOUT" if "TIMEOUT" in statuses else
               "SECURITY_REGRESSION" if "SECURITY_REGRESSION" in statuses else
               "POLICY_MISMATCH" if "POLICY_MISMATCH" in statuses else
               "FAIL" if "FAIL" in statuses else "PASS")
    return results, overall_rc, overall


def main(argv=None):
    parser = argparse.ArgumentParser(description="Diff policies, select risk-ranked tests, execute them, and create evidence.")
    parser.add_argument("--old-policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--new-policy", type=Path, default=DEFAULT_POLICY_V2)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dashboard", type=Path, default=DEFAULT_DASHBOARD)
    parser.add_argument("--base-url", default=os.getenv("AUTH_TRACE_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--execute", action="store_true", help="Execute only selected pytest node IDs; requires a running authorized target.")
    parser.add_argument("--fail-on-unmapped", action="store_true", help="Return non-zero when changed rules have no test mapping.")
    args = parser.parse_args(argv)

    old_policy = validate_policy(load_json(args.old_policy))
    new_policy = validate_policy(load_json(args.new_policy))
    mapping_doc = load_json(args.mapping)
    changes = diff_policies(old_policy, new_policy)
    validate_mapping_rule_ids(
        mapping_doc,
        set(rule_index(old_policy)) | set(rule_index(new_policy)),
    )
    plan = build_plan(changes, mapping_doc)
    missing_test_files = validate_nodeid_paths(mapping_doc)

    checks, return_code, execution_overall = [], 0, None
    if missing_test_files:
        return_code = 2
    if args.execute and not missing_test_files:
        expected_outcomes = {rule["id"]: rule["expected"] for rule in new_policy["rules"]}
        checks, return_code, execution_overall = run_selected(plan, args.base_url, expected_outcomes)
    if args.fail_on_unmapped and plan["unmapped_rules"]:
        return_code = max(return_code, 2)

    if missing_test_files:
        overall = "ERROR"
    elif args.execute:
        overall = execution_overall or "ERROR"
    elif plan["unmapped_rules"]:
        overall = "NEEDS_MAPPING"
    else:
        overall = "PLANNED"

    report = {
        "tool": "AuthTrace policy pipeline",
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": "1.1.0",
        "policy_versions": {
            "old": old_policy.get("policy_version", "unknown"),
            "new": new_policy.get("policy_version", "unknown"),
            "old_sha256": hashlib.sha256(
                json.dumps(old_policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "new_sha256": hashlib.sha256(
                json.dumps(new_policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        },
        "target": {
            "url": safe_target(args.base_url) if args.execute else None,
            "execution_requested": args.execute,
        },
        "summary": {"changed_rules": len(changes), "selected_tests": len(plan["selected_tests"]),
                    "unmapped_rules": len(plan["unmapped_rules"]), "missing_test_files": len(missing_test_files),
                    "tests_executed": len(checks),
                    "passed": sum(x["verdict"] == "PASS" for x in checks),
                    "failed": sum(x["verdict"] == "FAIL" for x in checks),
                    "errored": sum(x["verdict"] == "ERROR" for x in checks)},
        "changes": [{"rule_id": c["rule_id"], "change": c["change"],
                     "changed_fields": c.get("changed_fields", []), "risk_score": risk_score(c),
                     "risk_explanation": risk_explanation(c)} for c in changes],
        "plan": plan, "checks": checks,
        "coverage_gaps": {"unmapped_rules": plan["unmapped_rules"], "missing_test_nodeids": missing_test_files},
        "execution_status": ("NOT_REQUESTED" if not args.execute else
                             "NOT_RUN_INVALID_MAPPING" if missing_test_files else
                             "NOT_RUN_EMPTY_SELECTION" if not plan["selected_tests"] else overall),
        "overall": overall,
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
                      "execution_status": report["execution_status"],
                      "selected_tests": plan["selected_tests"], "unmapped_rules": plan["unmapped_rules"],
                      "missing_test_nodeids": missing_test_files,
                      "report": str(args.report), "dashboard": str(args.dashboard)}, indent=2))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
