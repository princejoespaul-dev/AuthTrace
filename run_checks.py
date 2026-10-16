"""Run bounded, read-only checks and write a sanitized JSON evidence report."""
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import httpx

BASE_URL = os.getenv("AUTH_TRACE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
EXPECT_VULNERABLE = os.getenv("AUTH_TRACE_EXPECT_VULNERABLE", "0") == "1"
ALLOW_STAGING = os.getenv("AUTHTRACE_ALLOW_STAGING", "0") == "1"
REPORT = Path("reports/latest.json")

def enforce_scope(base_url: str):
    parsed = urlparse(base_url)
    if parsed.scheme != "http" and parsed.scheme != "https":
        raise SystemExit("Blocked: target must use HTTP or HTTPS.")
    if not parsed.hostname:
        raise SystemExit("Blocked: target hostname missing.")
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except OSError as exc:
        raise SystemExit("Blocked: hostname could not be resolved.") from exc
    loopback = ip.startswith("127.") or parsed.hostname == "localhost"
    if not loopback and not ALLOW_STAGING:
        raise SystemExit("Blocked: non-loopback target. Use only authorized staging and explicitly set AUTHTRACE_ALLOW_STAGING=1.")
    if parsed.username or parsed.password:
        raise SystemExit("Blocked: credentials must not be embedded in the URL.")

def fetch(client, token, invoice_id):
    return client.get(
        f"/api/invoices/{invoice_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3.0,
        follow_redirects=False,
    )

def main():
    enforce_scope(BASE_URL)
    vulnerable = False
    checks = []
    with httpx.Client(base_url=BASE_URL, trust_env=False) as client:
        health = client.get("/health", timeout=3.0, follow_redirects=False)
        if health.status_code != 200:
            raise SystemExit(f"Demo API health check failed: HTTP {health.status_code}")
        mode = health.json().get("mode", "unknown")

        cases = [
            ("TC-OWN-READ", "token-user-a", "inv-a", "allow", "INV-READ-OWN"),
            ("TC-ADMIN-READ", "token-admin", "inv-b", "allow", "INV-READ-ADMIN"),
            ("TC-CROSS-USER", "token-user-a", "inv-b", "deny", "INV-READ-OTHER"),
        ]
        for test_id, token, invoice_id, expected, policy_id in cases:
            response = fetch(client, token, invoice_id)
            body = response.json() if "application/json" in response.headers.get("content-type", "") else {}
            owner = body.get("owner_id")
            if expected == "allow":
                observed_ok = response.status_code == 200 and owner is not None
                observed = "allow" if observed_ok else "deny_or_unexpected"
            else:
                observed_ok = response.status_code in (403, 404) and owner is None
                observed = "deny" if observed_ok else ("allow" if response.status_code == 200 and owner else "unexpected")
                if test_id == "TC-CROSS-USER" and observed == "allow":
                    vulnerable = True
            checks.append({
                "test_id": test_id,
                "policy_id": policy_id,
                "actor_label": "admin" if token == "token-admin" else "user-a",
                "object_fixture": invoice_id,
                "action": "read_invoice",
                "expected": expected,
                "observed": observed,
                "verdict": "PASS" if observed_ok == (expected == "allow") else "FAIL",
                "http_status": response.status_code,
                "evidence": {
                    "returned_owner_matches_fixture": bool(owner == ("user-a" if invoice_id == "inv-a" else "user-b")) if owner else False,
                    "response_body_captured": False,
                    "token_redacted": True
                }
            })

    # The cross-user denial rule is the important policy check. Avoid treating a successful HTTP request
    # as a test pass when the policy expected denial.
    for item in checks:
        if item["test_id"] == "TC-CROSS-USER":
            item["verdict"] = "FAIL" if item["observed"] == "allow" else ("PASS" if item["observed"] == "deny" else "INCONCLUSIVE")

    result = {
        "tool": "AuthTrace starter",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": BASE_URL,
        "target_mode": mode,
        "scope_note": "Synthetic local demo; sanitized report; no token values or response bodies recorded.",
        "overall": "VULNERABILITY_DETECTED" if vulnerable else ("NO_SEEDED_BOLA_OBSERVED" if all(c["verdict"] != "INCONCLUSIVE" for c in checks) else "INCONCLUSIVE"),
        "checks": checks,
        "limitations": ["Only three synthetic read checks were executed.", "This is not proof that the entire API is secure."]
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"\nSaved sanitized report to {REPORT}")

if __name__ == "__main__":
    main()
