"""Reliable lifecycle for tests that exercise the local synthetic authorization API."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

ROOT = Path(__file__).resolve().parent
API_URL = "http://127.0.0.1:8000"
_process = None


def _health_payload():
    try:
        with urlopen(f"{API_URL}/health", timeout=0.5) as response:
            payload = json.loads(response.read(4096).decode("utf-8"))
        if isinstance(payload, dict) and payload.get("status") == "ok" and payload.get("mode") in {"fixed", "vulnerable"}:
            return payload
        raise RuntimeError("Port 8000 responds, but it is not the AuthTrace synthetic API health endpoint.")
    except (URLError, TimeoutError, ConnectionError, json.JSONDecodeError):
        return None


def _api_probe():
    """Confirm the health response belongs to this API, not an unrelated local service."""
    try:
        with urlopen(f"{API_URL}/api/invoices/inv-a", timeout=1) as response:
            payload = json.loads(response.read(4096).decode("utf-8"))
            return payload.get("id") == "inv-a" and payload.get("owner_id") == "user-a"
    except Exception:
        # The endpoint is expected to reject unauthenticated requests. A real AuthTrace
        # API returns HTTP 401; the request handler itself is therefore probed separately below.
        try:
            from urllib.request import Request
            request = Request(f"{API_URL}/api/invoices/inv-a", headers={"Authorization": "Bearer token-user-a"})
            with urlopen(request, timeout=1) as response:
                payload = json.loads(response.read(4096).decode("utf-8"))
                return payload.get("id") == "inv-a" and payload.get("owner_id") == "user-a"
        except Exception:
            return False


def _port_open():
    with socket.socket() as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", 8000)) == 0


def _ensure_api():
    global _process
    health = _health_payload()
    if health is not None:
        if not _api_probe():
            raise RuntimeError("An HTTP service occupies 127.0.0.1:8000 but failed the AuthTrace synthetic API probe; refusing to test against it.")
        return
    if _port_open():
        raise RuntimeError("Port 8000 is occupied by an unrecognized service; refusing to start or test against it.")

    env = os.environ.copy()
    env["AUTH_TRACE_MODE"] = "fixed"
    _process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "demo_api:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if _process.poll() is not None:
            output = _process.stdout.read() if _process.stdout else ""
            raise RuntimeError("AuthTrace synthetic API failed to start. Startup output: " + output[-3000:])
        health = _health_payload()
        if health is not None:
            if not _api_probe():
                raise RuntimeError("Started service did not pass the AuthTrace synthetic API probe.")
            return
        time.sleep(0.2)
    _process.terminate()
    try:
        _process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        _process.kill()
        _process.wait(timeout=3)
    output = _process.stdout.read() if _process.stdout else ""
    raise RuntimeError("Timed out waiting for AuthTrace synthetic API readiness. Startup output: " + output[-3000:])


def pytest_runtest_setup(item):
    # The root-level tests exercise real HTTP behavior. Unit tests remain server-free.
    if Path(str(item.fspath)).resolve() == (ROOT / "test_authorization.py").resolve():
        _ensure_api()


def pytest_sessionfinish(session, exitstatus):
    global _process
    if _process is not None and _process.poll() is None:
        _process.terminate()
        try:
            _process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _process.kill()
            _process.wait(timeout=3)
        _process = None
