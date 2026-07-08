#!/bin/sh
# gen-dev-secrets.sh — Generate dev-only Docker secret files for Rendly (R-010, ADR-0010).
# Mirrors Anoryx-AI-Orchestrator's deploy/secrets/gen-dev-secrets.sh (O-008, ADR-0008).
#
# Run from the Rendly directory:
#   bash deploy/secrets/gen-dev-secrets.sh
#
# Idempotent: existing files are NEVER overwritten (re-run is safe).
# DO NOT use these values in production. See deploy/secrets/README.md.
#
# Files created in deploy/secrets/:
#   postgres_password           — "rendly" (matches postgres service default)
#   rendly_jwt_private_key_pem  — a freshly generated ES256 (P-256) private key, PKCS8 PEM

set -eu

SECRETS_DIR="$(dirname "$0")"

write_if_absent() {
    file="$1"
    value="$2"
    if [ -f "$file" ] && [ -s "$file" ]; then
        echo "gen-dev-secrets: $file already exists — skipped"
    else
        printf '%s' "$value" > "$file"
        echo "gen-dev-secrets: $file created"
    fi
}

gen_ec_p256_pem() {
    if command -v openssl >/dev/null 2>&1; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
    else
        python3 -c "
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
k = ec.generate_private_key(ec.SECP256R1())
print(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(), end='')
" 2>/dev/null || \
        python -c "
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
k = ec.generate_private_key(ec.SECP256R1())
print(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(), end='')
"
    fi
}

# 1. postgres_password — must match POSTGRES_PASSWORD default ("rendly").
write_if_absent "$SECRETS_DIR/postgres_password" "rendly"

# 2. rendly_jwt_private_key_pem — the ES256 (P-256) signing key (RENDLY_JWT_PRIVATE_KEY_PEM).
#    Fail-closed at app startup if absent/malformed/wrong-curve (rendly.auth.keys).
if [ ! -f "$SECRETS_DIR/rendly_jwt_private_key_pem" ] || [ ! -s "$SECRETS_DIR/rendly_jwt_private_key_pem" ]; then
    gen_ec_p256_pem > "$SECRETS_DIR/rendly_jwt_private_key_pem"
    echo "gen-dev-secrets: $SECRETS_DIR/rendly_jwt_private_key_pem created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/rendly_jwt_private_key_pem already exists — skipped"
fi

echo ""
echo "gen-dev-secrets: done. Files in $SECRETS_DIR:"
echo "  postgres_password   rendly_jwt_private_key_pem"
echo ""
echo "CHANGE IN PROD: use a strong random postgres password and a dedicated secret manager"
echo "(Vault / AWS-SM) or your KMS's own P-256 key for RENDLY_JWT_PRIVATE_KEY_PEM. Rotating"
echo "this key invalidates every outstanding access + refresh token (R-003)."
