"""Local-first AuthTrace control-center API.

Run with: uvicorn control_center:app --host 127.0.0.1 --port 8010
The demo API remains separate on 127.0.0.1:8000.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
REPORT_DIR = ROOT / "reports"
DB_PATH = REPORT_DIR / "authtrace.db"
PROPOSAL_PATH = ROOT / "policy.proposed.json"
DEFAULT_TARGET = "http://127.0.0.1:8000"
app = FastAPI(title="AuthTrace Control Center", version="0.1.0",
              description="Local-first API authorization testing workbench.")
if WEB_DIR.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect_db() -> sqlite3.Connection:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, status TEXT NOT NULL, target TEXT NOT NULL,
            started_at TEXT NOT NULL, finished_at TEXT, duration_seconds REAL,
            overall TEXT, summary_json TEXT NOT NULL DEFAULT '{}',
            report_json TEXT NOT NULL DEFAULT '{}', error TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'Open',
            updated_at TEXT NOT NULL
        )""")


init_db()


def safe_local_target(value: str) -> str:
    """Only allow explicitly local loopback HTTP targets for this first release."""
    parsed = urlparse(value)
    if parsed.scheme != "http" or not parsed.hostname:
        raise HTTPException(400, "Target must be a local HTTP URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(400, "Target URL cannot contain credentials, a query, or a fragment.")
    host = parsed.hostname.lower()
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise HTTPException(403, "Only loopback targets are enabled. External targets are not supported by this control center.")
    if parsed.path not in {"", "/"}:
        raise HTTPException(400, "Target URL must not include a path.")
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise HTTPException(400, "Invalid target port.") from exc
    return f"http://{host}:{port}"


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(404, f"Required file not found: {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(422, f"{path.name} contains invalid JSON at line {exc.lineno}, column {exc.colno}.") from exc
    if not isinstance(value, dict):
        raise HTTPException(422, f"{path.name} must contain a JSON object.")
    return value


def pipeline_module():
    try:
        import authtrace_pipeline
        return authtrace_pipeline
    except Exception as exc:
        raise HTTPException(500, f"Policy pipeline could not be loaded: {type(exc).__name__}") from exc


@app.get("/", response_class=HTMLResponse)
def home():
    index = WEB_DIR / "index.html"
    if not index.is_file():
        return HTMLResponse("<h1>AuthTrace</h1><p>Dashboard UI is not installed.</p>", status_code=503)
    return HTMLResponse(index.read_text(encoding="utf-8"))


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "AuthTrace Control Center", "time": now(),
            "demo_api_url": DEFAULT_TARGET}


@app.get("/api/overview")
def overview():
    with connect_db() as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 8").fetchall()
        counts = conn.execute("""SELECT
            COUNT(*) total,
            SUM(CASE WHEN overall IN ('NO_SEEDED_BOLA_OBSERVED','PASS') THEN 1 ELSE 0 END) passed,
            SUM(CASE WHEN overall IN ('VULNERABILITY_DETECTED','FAIL') THEN 1 ELSE 0 END) failed,
            SUM(CASE WHEN overall IN ('INCONCLUSIVE','ERROR') THEN 1 ELSE 0 END) inconclusive
            FROM runs""").fetchone()
        open_findings = conn.execute("SELECT COUNT(*) n FROM findings WHERE status='Open'").fetchone()["n"]
    latest = read_json(REPORT_DIR / "latest.json") if (REPORT_DIR / "latest.json").exists() else {}
    return {
        "metrics": {"total_runs": counts["total"] or 0, "passed_runs": counts["passed"] or 0,
                    "failed_runs": counts["failed"] or 0, "inconclusive_runs": counts["inconclusive"] or 0,
                    "open_findings": open_findings,
                    "policy_version": str(latest.get("policy_versions", {}).get("new", "—")),
                    "last_successful_run": next((r["finished_at"] for r in rows
                        if r["overall"] in {"NO_SEEDED_BOLA_OBSERVED", "PASS"}), None)},
        "recent_runs": [run_row(row) for row in rows],
        "pipeline": {"available": (ROOT / "authtrace_pipeline.py").is_file(),
                     "policy_files": [p.name for p in (ROOT / "policy.json", ROOT / "policy.v2.json") if p.is_file()]},
    }


def run_row(row):
    return {"id": row["id"], "status": row["status"], "target": row["target"],
            "started_at": row["started_at"], "finished_at": row["finished_at"],
            "duration_seconds": row["duration_seconds"], "overall": row["overall"],
            "summary": json.loads(row["summary_json"] or "{}"), "error": row["error"]}


@app.get("/api/runs")
def list_runs(limit: int = 50):
    limit = max(1, min(limit, 200))
    with connect_db() as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    return {"runs": [run_row(row) for row in rows]}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Run not found.")
    result = run_row(row)
    result["report"] = json.loads(row["report_json"] or "{}")
    return result


class RunRequest(BaseModel):
    target: str = DEFAULT_TARGET
    confirm_local_target: bool = False


@app.post("/api/runs", status_code=202)
def start_run(request: RunRequest):
    if not request.confirm_local_target:
        raise HTTPException(400, "Confirm that this run targets the local synthetic demo API.")
    target = safe_local_target(request.target)
    if target != DEFAULT_TARGET:
        raise HTTPException(403, "Only the default synthetic demo API at 127.0.0.1:8000 is enabled.")
    module = pipeline_module()
    baseline = read_json(ROOT / "policy.json")
    proposal = read_json(PROPOSAL_PATH if PROPOSAL_PATH.exists() else ROOT / "policy.v2.json")
    mapping = read_json(ROOT / "test_mapping.json")
    try:
        module.validate_policy(baseline)
        module.validate_policy(proposal)
        module.validate_mapping_rule_ids(mapping, set(module.rule_index(baseline)) | set(module.rule_index(proposal)))
    except SystemExit as exc:
        raise HTTPException(422, str(exc)) from exc
    changes = module.diff_policies(baseline, proposal)
    plan = module.build_plan(changes, mapping)
    missing = module.validate_nodeid_paths(mapping, ROOT)
    if missing:
        raise HTTPException(422, "Mapped test files are missing or outside the repository: " + ", ".join(missing))
    if plan["unmapped_rules"]:
        # A gap is recorded, not silently treated as successful coverage.
        coverage_gaps = list(plan["unmapped_rules"])
    else:
        coverage_gaps = []
    if not plan["selected_tests"]:
        raise HTTPException(422, "No tests were selected because the policies have no mapped changes.")
    run_id, started_at = str(uuid.uuid4()), now()
    with connect_db() as conn:
        conn.execute("INSERT INTO runs(id,status,target,started_at) VALUES(?,?,?,?)",
                     (run_id, "RUNNING", target, started_at))
    started = time.monotonic()
    expected = {rule["id"]: rule["expected"] for rule in proposal["rules"]}
    try:
        checks, rc, overall = module.run_selected(plan, target, expected, timeout_seconds=25)
        duration = round(time.monotonic() - started, 3)
        summary = {"checks": len(checks),
                   "passed": sum(x["verdict"] == "PASS" for x in checks),
                   "failed": sum(x["verdict"] in {"FAIL", "POLICY_MISMATCH", "SECURITY_REGRESSION"} for x in checks),
                   "errored": sum(x["verdict"] == "ERROR" for x in checks),
                   "timed_out": sum(x["verdict"] == "TIMEOUT" for x in checks),
                   "coverage_gaps": coverage_gaps}
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        report = {"run_id": run_id, "generated_at": now(), "overall": overall,
                  "target": target, "baseline_sha256": digest(baseline), "proposal_sha256": digest(proposal),
                  "changed_rules": changes, "selected_tests": plan["selected_tests"],
                  "selection": plan["items"], "coverage_gaps": coverage_gaps,
                  "checks": checks, "summary": summary,
                  "limitations": ["A passing selected regression suite does not prove the whole API secure."]}
        status = "COMPLETED" if overall not in {"ERROR", "TIMEOUT"} else "ERROR"
        error = None if status == "COMPLETED" else "One or more selected tests could not complete; inspect per-test error classifications."
        with connect_db() as conn:
            conn.execute("""UPDATE runs SET status=?,finished_at=?,duration_seconds=?,overall=?,
                summary_json=?,report_json=?,error=? WHERE id=?""",
                (status, now(), duration, overall, json.dumps(summary), json.dumps(report), error, run_id))
            if any(x.get("verdict") == "SECURITY_REGRESSION" for x in checks):
                conn.execute("INSERT OR IGNORE INTO findings(id,status,updated_at) VALUES(?,?,?)",
                             ("BOLA-CROSS-USER", "Open", now()))
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        (REPORT_DIR / "latest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception as exc:
        with connect_db() as conn:
            conn.execute("UPDATE runs SET status='ERROR',finished_at=?,duration_seconds=?,overall='ERROR',error=? WHERE id=?",
                         (now(), round(time.monotonic() - started, 3), f"Execution failed ({type(exc).__name__}).", run_id))
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    return run_row(row)


@app.get("/api/policy-diff")
def policy_diff():
    module = pipeline_module()
    old = read_json(ROOT / "policy.json")
    new = read_json(PROPOSAL_PATH if PROPOSAL_PATH.exists() else ROOT / "policy.v2.json")
    try:
        module.validate_policy(old)
        module.validate_policy(new)
    except SystemExit as exc:
        raise HTTPException(422, str(exc)) from exc
    changes = module.diff_policies(old, new)
    return {"old_version": old.get("policy_version", "unknown"),
            "new_version": new.get("policy_version", "unknown"),
            "old_sha256": hashlib.sha256(json.dumps(old, sort_keys=True).encode()).hexdigest(),
            "new_sha256": hashlib.sha256(json.dumps(new, sort_keys=True).encode()).hexdigest(),
            "changes": [{"rule_id": c["rule_id"], "change": c["change"],
                         "changed_fields": c.get("changed_fields", []),
                         "before": c.get("before"), "after": c.get("after"),
                         "risk_score": module.risk_score(c),
                         "risk_explanation": module.risk_explanation(c)} for c in changes]}


@app.get("/api/regression-plan")
def regression_plan():
    module = pipeline_module()
    old = read_json(ROOT / "policy.json")
    new = read_json(PROPOSAL_PATH if PROPOSAL_PATH.exists() else ROOT / "policy.v2.json")
    mapping = read_json(ROOT / "test_mapping.json")
    try:
        module.validate_policy(old)
        module.validate_policy(new)
        module.validate_mapping_rule_ids(mapping, set(module.rule_index(old)) | set(module.rule_index(new)))
    except SystemExit as exc:
        raise HTTPException(422, str(exc)) from exc
    changes = module.diff_policies(old, new)
    module.validate_mapping_rule_ids(mapping, set(module.rule_index(old)) | set(module.rule_index(new)))
    plan = module.build_plan(changes, mapping)
    missing = module.validate_nodeid_paths(mapping, ROOT)
    return {"planned_only": True, "selected_tests": plan["selected_tests"], "items": plan["items"],
            "changes": changes, "baseline_sha256": hashlib.sha256(json.dumps(old, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "proposal_sha256": hashlib.sha256(json.dumps(new, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "unmapped_rules": plan["unmapped_rules"], "missing_test_nodeids": missing,
            "old_policy_version": old.get("policy_version", "unknown"),
            "new_policy_version": new.get("policy_version", "unknown")}


@app.get("/api/findings")
def findings():
    with connect_db() as conn:
        rows = conn.execute("SELECT id,status,updated_at FROM findings ORDER BY updated_at DESC").fetchall()
    return {"findings": [{"id": r["id"], "title": "Cross-user invoice access (BOLA)",
        "severity": "High", "confidence": "High", "status": r["status"],
        "explanation": "The synthetic demo returned another user's invoice to a non-owner.",
        "remediation": "Enforce server-side object ownership checks before returning invoice data.",
        "updated_at": r["updated_at"]} for r in rows]}


class FindingUpdate(BaseModel):
    status: str = Field(pattern="^(Open|In Review|Fixed|Accepted Risk)$")


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: str, update: FindingUpdate):
    with connect_db() as conn:
        cur = conn.execute("UPDATE findings SET status=?,updated_at=? WHERE id=?",
                           (update.status, now(), finding_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Finding not found.")
    return {"id": finding_id, "status": update.status, "updated_at": now()}


@app.get("/api/reports/latest")
def latest_report():
    path = REPORT_DIR / "latest.json"
    if not path.is_file():
        raise HTTPException(404, "No report exists yet. Run the local authorization checks first.")
    return read_json(path)


@app.get("/api/reports/latest/download")
def download_latest_report():
    path = REPORT_DIR / "latest.json"
    if not path.is_file():
        raise HTTPException(404, "No report exists yet.")
    return FileResponse(path, filename="authtrace-latest-report.json", media_type="application/json")
