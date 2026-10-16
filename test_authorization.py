import os
import httpx
import pytest

BASE_URL = os.getenv("AUTH_TRACE_BASE_URL", "http://127.0.0.1:8000")
EXPECT_VULNERABLE = os.getenv("AUTH_TRACE_EXPECT_VULNERABLE", "0") == "1"

def request_invoice(token, invoice_id):
    with httpx.Client(base_url=BASE_URL, timeout=3.0, follow_redirects=False) as client:
        return client.get(
            f"/api/invoices/{invoice_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

def test_user_can_read_own_invoice():
    response = request_invoice("token-user-a", "inv-a")
    assert response.status_code == 200
    assert response.json().get("owner_id") == "user-a"

def test_admin_can_read_other_users_invoice():
    response = request_invoice("token-admin", "inv-b")
    assert response.status_code == 200
    assert response.json().get("owner_id") == "user-b"

def test_cross_user_access_matches_declared_mode():
    response = request_invoice("token-user-a", "inv-b")
    if EXPECT_VULNERABLE:
        # The test detects the seeded vulnerability; this is not a security pass.
        assert response.status_code == 200 and response.json().get("owner_id") == "user-b"
    else:
        assert response.status_code in (403, 404)
