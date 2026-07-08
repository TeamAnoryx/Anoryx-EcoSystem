#!/bin/sh
# gen-k8s-secret.sh — create the Rendly env Secret in a K8s namespace WITHOUT writing any
# secret into the repo. Mirrors Anoryx-AI-Orchestrator's deploy/helm/gen-k8s-secret.sh
# (O-008, ADR-0008).
#
# Creates, from a freshly generated dev ES256 key:
#   Secret <release>-rendly-env  (RENDLY_JWT_PRIVATE_KEY_PEM)
#
# The bundled-Postgres password is rendered by the chart itself (dev-grade default), so it
# is NOT created here.
#
# Idempotent: re-running applies (create-or-update), never errors on existing. NOTE: unlike
# a random-bytes secret, re-running this ROTATES the signing key — every outstanding
# access/refresh token becomes invalid. That's expected for a dev/demo helper; don't re-run
# it against a Secret real users are relying on.
#
# Usage (from the Rendly directory):
#   bash deploy/helm/gen-k8s-secret.sh <namespace> [release]
#   # default release: rendly  ->  Secret name: rendly-rendly-env
#
# CHANGE IN PROD: use a real secret manager (Vault / External Secrets Operator) or your KMS's
# own P-256 key; these values are dev-grade and ephemeral.

set -eu

NAMESPACE="${1:-}"
RELEASE="${2:-rendly}"

if [ -z "$NAMESPACE" ]; then
    echo "usage: $0 <namespace> [release]" >&2
    exit 2
fi

FULLNAME="${RELEASE}-rendly"
ENV_SECRET="${FULLNAME}-env"

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

# Ensure the namespace exists (idempotent).
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- env Secret (apply = create-or-update; never errors on re-run) ------------ #
# --from-file preserves the PEM's exact multi-line formatting (a literal that a
# --from-literal argument would mangle on some shells).
TMP_PEM="$(mktemp)"
trap 'rm -f "$TMP_PEM"' EXIT
gen_ec_p256_pem > "$TMP_PEM"

kubectl create secret generic "$ENV_SECRET" -n "$NAMESPACE" \
    --from-file=RENDLY_JWT_PRIVATE_KEY_PEM="$TMP_PEM" \
    --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f - >/dev/null
echo "gen-k8s-secret: Secret $ENV_SECRET applied"

echo ""
echo "gen-k8s-secret: done. Install with:"
echo "  helm install $RELEASE deploy/helm/rendly -n $NAMESPACE \\"
echo "    -f deploy/helm/rendly/values.example.yaml --set envSecret=$ENV_SECRET"
