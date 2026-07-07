#!/bin/sh
# gen-k8s-secret.sh — create the Anoryx-AI-Orchestrator env Secret in a K8s
# namespace WITHOUT writing any secret into the repo. Mirrors Anoryx-Sentinel's
# deploy/helm/gen-k8s-secret.sh (ADR-0027 D3).
#
# Creates, from freshly generated dev values:
#   Secret <release>-orchestrator-env  (ORCH_INGEST_HMAC_SECRET, ORCH_ADMIN_TOKEN)
#
# The bundled-Postgres password is rendered by the chart itself (dev-grade
# default), so it is NOT created here.
#
# Idempotent: re-running applies (create-or-update), never errors on existing.
#
# Usage (from the Anoryx-AI-Orchestrator directory):
#   bash deploy/helm/gen-k8s-secret.sh <namespace> [release]
#   # default release: orchestrator  ->  Secret name: orchestrator-orchestrator-env
#
# CHANGE IN PROD: use a real secret manager (Vault / External Secrets Operator);
# these values are dev-grade and ephemeral.

set -eu

NAMESPACE="${1:-}"
RELEASE="${2:-orchestrator}"

if [ -z "$NAMESPACE" ]; then
    echo "usage: $0 <namespace> [release]" >&2
    exit 2
fi

FULLNAME="${RELEASE}-orchestrator"
ENV_SECRET="${FULLNAME}-env"

rand_hex() { openssl rand -hex "$1" 2>/dev/null || \
    python3 -c "import os,sys;sys.stdout.write(os.urandom($1).hex())" 2>/dev/null || \
    python  -c "import os,sys;sys.stdout.write(os.urandom($1).hex())"; }

# Ensure the namespace exists (idempotent).
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- env Secret (apply = create-or-update; never errors on re-run) ------------ #
kubectl create secret generic "$ENV_SECRET" -n "$NAMESPACE" \
    --from-literal=ORCH_INGEST_HMAC_SECRET="$(rand_hex 32)" \
    --from-literal=ORCH_ADMIN_TOKEN="$(rand_hex 32)" \
    --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f - >/dev/null
echo "gen-k8s-secret: Secret $ENV_SECRET applied"

echo ""
echo "gen-k8s-secret: done. Install with:"
echo "  helm install $RELEASE deploy/helm/orchestrator -n $NAMESPACE \\"
echo "    -f deploy/helm/orchestrator/values.example.yaml --set envSecret=$ENV_SECRET"
