"""Real HTTP authorization matrix. OpenSSL signs local demo tokens only."""
import base64
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
BASE = os.getenv("BASE_URL", "http://127.0.0.1:8085")

def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")

def token(subject, tenant, expired=False):
    now = int(time.time())
    header = encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = encode(json.dumps({"sub": subject, "tenant": tenant, "iss": "https://local-issuer.example", "aud": "tenant-gateway", "iat": now-120, "exp": now-60 if expired else now+300}).encode())
    message = header + b"." + payload
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(ROOT / ".local/private.pem")], input=message, capture_output=True, check=True).stdout
    return (message + b"." + encode(signature)).decode()

checks = 0

def call(method, path, subject="alice", tenant="acme", expected=200, body=None, expired=False, headers=None):
    global checks
    request_headers = {"Authorization": "Bearer " + token(subject, tenant, expired), "Content-Type": "application/json"}
    request_headers.update(headers or {})
    request = Request(BASE + path, method=method, headers=request_headers, data=None if body is None else json.dumps(body).encode())
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        if response.status != expected:
            raise RuntimeError(f"{method} {path}: expected {expected}, got {response.status}: {raw.decode()}")
        checks += 1
        return json.loads(raw) if raw and response.headers.get("Content-Type", "").startswith("application/json") else None

path = "/v1/tenants/acme/scopes/team-a/services/billing/invoices"
call("GET", path)
call("POST", path, expected=403, body={"id": "forbidden", "amount_cents": 1})
call("GET", path, tenant="globex", expected=403)
call("GET", path, subject="unknown", expected=403)
call("GET", path, expired=True, expected=401)
call("GET", path+"/invoice-2", expected=404)
call("GET", path, headers={"X-Tenant-ID":"globex", "X-Roles":"manager"})
call("DELETE", path+"/invoice-1", subject="carol", expected=403)
call("GET", path.replace("team-a", "team-b"), subject="bob", expected=403)
call("GET", path.replace("invoices", "admin"), subject="carol", expected=404)
hr = "/v1/tenants/acme/scopes/team-a/services/hr/employees"
call("GET", hr, expected=403)
assert call("GET", hr, subject="helen")[0]["tenant"] == "acme"
identifier = "demo-" + uuid4().hex[:12]
created = call("POST", path, subject="bob", expected=201, body={"id":identifier, "amount_cents":1200})
assert created["tenant"] == "acme" and created["scope"] == "team-a"
call("PATCH", path+"/"+identifier, subject="bob", body={"amount_cents":1400})
assert call("GET", path+"/"+identifier)["amount_cents"] == 1400
call("DELETE", path+"/"+identifier, subject="bob", expected=403)
other = "/v1/tenants/globex/scopes/root/services/billing/invoices"
call("POST", other, tenant="globex", expected=201, body={"id":"globex-"+identifier,"amount_cents":50})
call("DELETE", other+"/globex-"+identifier, tenant="globex", expected=204)
print(f"PASS: {checks} HTTP checks: company/scope/service/CRUD permissions, inheritance, deny priority, object isolation, expired tokens, spoofed headers.")
