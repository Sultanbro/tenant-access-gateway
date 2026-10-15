"""Generate local demo credentials; never overwrite existing keys."""
import json
import secrets
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
local = root / ".local"
local.mkdir(mode=0o700, exist_ok=True)
private = local / "private.pem"
public = local / "public.pem"
if not private.exists():
    with private.open("xb") as output:
        private.chmod(0o600)
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"], stdout=output, stderr=subprocess.DEVNULL, check=True)
if not public.exists():
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True)
    public.chmod(0o644)
config = root / ".env"
if not config.exists():
    keys = {"billing": secrets.token_hex(32), "hr": secrets.token_hex(32)}
    with config.open("x") as output:
        config.chmod(0o600)
        output.write("JWT_ISSUER=https://local-issuer.example\nJWT_AUDIENCE=tenant-gateway\nJWT_PUBLIC_KEY_FILE=.local/public.pem\n")
        output.write("UPSTREAM_KEYS_JSON='" + json.dumps(keys) + "'\n")
        for name, key in keys.items():
            output.write(name.upper() + "_SIGNING_KEY=" + key + "\n")
print("Local demo keys are ready. Existing files were preserved.")
