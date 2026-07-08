#!/bin/sh
# gen-dev-secrets.sh — Generate dev-only Docker secret files for
# Anoryx-AI-Orchestrator (O-008, ADR-0008). Mirrors Anoryx-Sentinel's
# deploy/secrets/gen-dev-secrets.sh (F-010, ADR-0012).
#
# Run from the Anoryx-AI-Orchestrator directory:
#   bash deploy/secrets/gen-dev-secrets.sh
#
# Idempotent: existing files are NEVER overwritten (re-run is safe).
# DO NOT use these values in production. See deploy/secrets/README.md.
#
# Files created in deploy/secrets/:
#   postgres_password        — "orchestrator" (matches postgres service default)
#   orch_ingest_hmac_secret  — random 48-byte base64 HMAC key
#   orch_admin_token         — random 48-byte url-safe base64 operator token

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

random_base64() {
    bytes="$1"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 "$bytes" | tr -d '\n'
    else
        python3 -c "import base64,os,sys; sys.stdout.write(base64.urlsafe_b64encode(os.urandom($bytes)).decode())" \
            2>/dev/null || \
        python  -c "import base64,os,sys; sys.stdout.write(base64.urlsafe_b64encode(os.urandom($bytes)).decode())"
    fi
}

# 1. postgres_password — must match POSTGRES_PASSWORD default ("orchestrator").
write_if_absent "$SECRETS_DIR/postgres_password" "orchestrator"

# 2. orch_ingest_hmac_secret — random 48-byte base64 HMAC key (ORCH_INGEST_HMAC_SECRET).
if [ ! -f "$SECRETS_DIR/orch_ingest_hmac_secret" ] || [ ! -s "$SECRETS_DIR/orch_ingest_hmac_secret" ]; then
    random_base64 48 > "$SECRETS_DIR/orch_ingest_hmac_secret"
    echo "gen-dev-secrets: $SECRETS_DIR/orch_ingest_hmac_secret created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/orch_ingest_hmac_secret already exists — skipped"
fi

# 3. orch_admin_token — random 48-byte operator token (ORCH_ADMIN_TOKEN).
if [ ! -f "$SECRETS_DIR/orch_admin_token" ] || [ ! -s "$SECRETS_DIR/orch_admin_token" ]; then
    random_base64 48 > "$SECRETS_DIR/orch_admin_token"
    echo "gen-dev-secrets: $SECRETS_DIR/orch_admin_token created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/orch_admin_token already exists — skipped"
fi

echo ""
echo "gen-dev-secrets: done. Files in $SECRETS_DIR:"
echo "  postgres_password   orch_ingest_hmac_secret   orch_admin_token"
echo ""
echo "CHANGE IN PROD: use a strong random postgres password and a dedicated"
echo "secret manager (Vault / AWS-SM) for orch_ingest_hmac_secret + orch_admin_token."
