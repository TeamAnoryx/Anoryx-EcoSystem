#!/bin/sh
# gen-dev-secrets.sh — Generate dev-only Docker secret files for Delta
# (D-010). Mirrors Anoryx-AI-Orchestrator's deploy/secrets/gen-dev-secrets.sh
# (O-008, ADR-0008), itself mirroring Anoryx-Sentinel's
# deploy/secrets/gen-dev-secrets.sh (F-010, ADR-0012).
#
# Run from the Delta directory:
#   bash deploy/secrets/gen-dev-secrets.sh
#
# Idempotent: existing files are NEVER overwritten (re-run is safe).
# DO NOT use these values in production. See deploy/secrets/README.md.
#
# Files created in deploy/secrets/:
#   postgres_password                  — "delta" (matches postgres service default)
#   delta_ingest_hmac_secret           — random 48-byte base64 HMAC key
#   delta_revenue_ingest_hmac_secret   — random 48-byte base64 HMAC key (X-005 revenue seam)
#   orch_service_token                 — random 48-byte url-safe base64 Bearer token
#   delta_admin_token                  — random 48-byte url-safe base64 break-glass token

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

# 1. postgres_password — must match POSTGRES_PASSWORD default ("delta").
write_if_absent "$SECRETS_DIR/postgres_password" "delta"

# 2. delta_ingest_hmac_secret — random 48-byte base64 HMAC key (DELTA_INGEST_HMAC_SECRET).
if [ ! -f "$SECRETS_DIR/delta_ingest_hmac_secret" ] || [ ! -s "$SECRETS_DIR/delta_ingest_hmac_secret" ]; then
    random_base64 48 > "$SECRETS_DIR/delta_ingest_hmac_secret"
    echo "gen-dev-secrets: $SECRETS_DIR/delta_ingest_hmac_secret created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/delta_ingest_hmac_secret already exists — skipped"
fi

# 2b. delta_revenue_ingest_hmac_secret — DEDICATED per-source revenue-ingest HMAC key
#     (DELTA_REVENUE_INGEST_HMAC_SECRET, X-005). MUST differ from delta_ingest_hmac_secret.
if [ ! -f "$SECRETS_DIR/delta_revenue_ingest_hmac_secret" ] || [ ! -s "$SECRETS_DIR/delta_revenue_ingest_hmac_secret" ]; then
    random_base64 48 > "$SECRETS_DIR/delta_revenue_ingest_hmac_secret"
    echo "gen-dev-secrets: $SECRETS_DIR/delta_revenue_ingest_hmac_secret created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/delta_revenue_ingest_hmac_secret already exists — skipped"
fi

# 3. orch_service_token — random 48-byte Bearer token (ORCH_SERVICE_TOKEN).
if [ ! -f "$SECRETS_DIR/orch_service_token" ] || [ ! -s "$SECRETS_DIR/orch_service_token" ]; then
    random_base64 48 > "$SECRETS_DIR/orch_service_token"
    echo "gen-dev-secrets: $SECRETS_DIR/orch_service_token created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/orch_service_token already exists — skipped"
fi

# 4. delta_admin_token — random 48-byte break-glass token (DELTA_ADMIN_TOKEN).
if [ ! -f "$SECRETS_DIR/delta_admin_token" ] || [ ! -s "$SECRETS_DIR/delta_admin_token" ]; then
    random_base64 48 > "$SECRETS_DIR/delta_admin_token"
    echo "gen-dev-secrets: $SECRETS_DIR/delta_admin_token created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/delta_admin_token already exists — skipped"
fi

echo ""
echo "gen-dev-secrets: done. Files in $SECRETS_DIR:"
echo "  postgres_password   delta_ingest_hmac_secret   delta_revenue_ingest_hmac_secret"
echo "  orch_service_token   delta_admin_token"
echo ""
echo "CHANGE IN PROD: use a strong random postgres password and a dedicated"
echo "secret manager (Vault / AWS-SM) for delta_ingest_hmac_secret,"
echo "delta_revenue_ingest_hmac_secret, orch_service_token, and delta_admin_token."
