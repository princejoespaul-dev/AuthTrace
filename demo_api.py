import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AuthTrace Synthetic Demo API")

# The dashboard runs on port 8010 and the synthetic demo API on port 8000.
# Permit only the local dashboard origins; do not use a wildcard for auth headers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8010",
        "http://localhost:8010",
    ],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

MODE = os.getenv("AUTH_TRACE_MODE", "fixed").strip().lower()
if MODE not in {"fixed", "vulnerable"}:
    raise RuntimeError("AUTH_TRACE_MODE must be 'fixed' or 'vulnerable'")

USERS = {
    "token-user-a": {"user_id": "user-a", "role": "user"},
    "token-user-b": {"user_id": "user-b", "role": "user"},
    "token-admin": {"user_id": "admin", "role": "admin"},
}
INVOICES = {
    "inv-a": {"id": "inv-a", "owner_id": "user-a", "amount": 120, "currency": "INR"},
    "inv-b": {"id": "inv-b", "owner_id": "user-b", "amount": 250, "currency": "INR"},
}

def current_actor(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.removeprefix("Bearer ").strip()
    actor = USERS.get(token)
    if actor is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return actor

@app.get("/health")
def health():
    return {"status": "ok", "mode": MODE}

@app.get("/api/invoices/{invoice_id}")
def read_invoice(invoice_id: str, authorization: str | None = Header(default=None)):
    actor = current_actor(authorization)
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=404, detail="Not found")

    # Deliberately seeded BOLA flaw for local training only.
    if MODE == "fixed":
        if actor["role"] != "admin" and invoice["owner_id"] != actor["user_id"]:
            # 404 is a valid denial strategy; do not rely on status code alone in general.
            raise HTTPException(status_code=404, detail="Not found")

    return invoice
