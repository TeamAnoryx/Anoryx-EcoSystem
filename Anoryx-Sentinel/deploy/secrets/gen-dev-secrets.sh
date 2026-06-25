#!/bin/sh
# gen-dev-secrets.sh — Generate dev-only Docker secret files for Anoryx Sentinel.
#
# Run from the Anoryx-Sentinel directory:
#   bash deploy/secrets/gen-dev-secrets.sh
#
# Idempotent: existing files are NEVER overwritten (re-run is safe).
# DO NOT use these values in production. See deploy/secrets/README.md.
#
# Files created in deploy/secrets/:
#   postgres_password  — "sentinel" (matches postgres service default)
#   redis_password     — (empty)    — bundled Redis has no auth
#   sentinel_key_secret — random 48-byte base64 HMAC key
#   admin_token        — random 48-byte url-safe base64 break-glass token
#   session_secret     — random 32-byte base64 session HMAC key

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

write_empty_if_absent() {
    file="$1"
    if [ -f "$file" ]; then
        echo "gen-dev-secrets: $file already exists — skipped"
    else
        : > "$file"
        echo "gen-dev-secrets: $file created (empty)"
    fi
}

random_base64() {
    bytes="$1"
    # Use openssl if available, else python3/python fallback.
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 "$bytes" | tr -d '\n'
    else
        python3 -c "import base64,os,sys; sys.stdout.write(base64.urlsafe_b64encode(os.urandom($bytes)).decode())" \
            2>/dev/null || \
        python  -c "import base64,os,sys; sys.stdout.write(base64.urlsafe_b64encode(os.urandom($bytes)).decode())"
    fi
}

# 1. postgres_password — must match POSTGRES_PASSWORD default ("sentinel").
write_if_absent "$SECRETS_DIR/postgres_password" "sentinel"

# 2. redis_password — empty (bundled Redis has no requirepass).
write_empty_if_absent "$SECRETS_DIR/redis_password"

# 3. sentinel_key_secret — random 48-byte base64 HMAC key for virtual API keys.
if [ ! -f "$SECRETS_DIR/sentinel_key_secret" ] || [ ! -s "$SECRETS_DIR/sentinel_key_secret" ]; then
    random_base64 48 > "$SECRETS_DIR/sentinel_key_secret"
    echo "gen-dev-secrets: $SECRETS_DIR/sentinel_key_secret created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/sentinel_key_secret already exists — skipped"
fi

# 4. admin_token — random 48-byte break-glass token for /admin/* auth.
if [ ! -f "$SECRETS_DIR/admin_token" ] || [ ! -s "$SECRETS_DIR/admin_token" ]; then
    random_base64 48 > "$SECRETS_DIR/admin_token"
    echo "gen-dev-secrets: $SECRETS_DIR/admin_token created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/admin_token already exists — skipped"
fi

# 5. session_secret — random 32-byte HMAC key for the admin console session cookie.
if [ ! -f "$SECRETS_DIR/session_secret" ] || [ ! -s "$SECRETS_DIR/session_secret" ]; then
    random_base64 32 > "$SECRETS_DIR/session_secret"
    echo "gen-dev-secrets: $SECRETS_DIR/session_secret created"
else
    echo "gen-dev-secrets: $SECRETS_DIR/session_secret already exists — skipped"
fi

echo ""
echo "gen-dev-secrets: done. Files in $SECRETS_DIR:"
echo "  postgres_password   redis_password   sentinel_key_secret   admin_token   session_secret"
echo ""
echo "CHANGE IN PROD: use strong random passwords for postgres_password and a"
echo "dedicated secret manager (Vault / AWS-SM) for admin_token + session_secret."
