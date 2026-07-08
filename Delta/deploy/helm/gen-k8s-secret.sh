#!/bin/sh
# gen-k8s-secret.sh — create the Delta env Secret in a K8s namespace WITHOUT
# writing any secret into the repo. Mirrors Anoryx-AI-Orchestrator's
# deploy/helm/gen-k8s-secret.sh (O-008, ADR-0008), itself mirroring
# Anoryx-Sentinel's deploy/helm/gen-k8s-secret.sh (ADR-0027 D3).
#
# Creates, from freshly generated dev values:
#   Secret <release>-delta-env  (DELTA_INGEST_HMAC_SECRET, DELTA_ADMIN_TOKEN,
#                                 ORCH_SERVICE_TOKEN)
#
# The bundled-Postgres password is rendered by the chart itself (dev-grade
# default), so it is NOT created here.
#
# ORCH_SERVICE_TOKEN is generated even though a minimal deploy defaults
# budgetEngineEnabled/killSwitchEnabled to false (so it goes unused) — this
# keeps the Secret shape stable regardless of whether enforcement publishing
# is later turned on with `--set budgetEngineEnabled=true`.
#
# Idempotent: re-running applies (create-or-update), never errors on existing.
#
# Usage (from the Delta directory):
#   bash deploy/helm/gen-k8s-secret.sh <namespace> [release]
#   # default release: delta  ->  Secret name: delta-delta-env
#
# CHANGE IN PROD: use a real secret manager (Vault / External Secrets Operator);
# these values are dev-grade and ephemeral.

set -eu

NAMESPACE="${1:-}"
RELEASE="${2:-delta}"

if [ -z "$NAMESPACE" ]; then
    echo "usage: $0 <namespace> [release]" >&2
    exit 2
fi

FULLNAME="${RELEASE}-delta"
ENV_SECRET="${FULLNAME}-env"

rand_hex() { openssl rand -hex "$1" 2>/dev/null || \
    python3 -c "import os,sys;sys.stdout.write(os.urandom($1).hex())" 2>/dev/null || \
    python  -c "import os,sys;sys.stdout.write(os.urandom($1).hex())"; }

# Ensure the namespace exists (idempotent).
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- env Secret (apply = create-or-update; never errors on re-run) ------------ #
kubectl create secret generic "$ENV_SECRET" -n "$NAMESPACE" \
    --from-literal=DELTA_INGEST_HMAC_SECRET="$(rand_hex 32)" \
    --from-literal=DELTA_ADMIN_TOKEN="$(rand_hex 32)" \
    --from-literal=ORCH_SERVICE_TOKEN="$(rand_hex 32)" \
    --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f - >/dev/null
echo "gen-k8s-secret: Secret $ENV_SECRET applied"

echo ""
echo "gen-k8s-secret: done. Install with:"
echo "  helm install $RELEASE deploy/helm/delta -n $NAMESPACE \\"
echo "    -f deploy/helm/delta/values.example.yaml --set envSecret=$ENV_SECRET"
