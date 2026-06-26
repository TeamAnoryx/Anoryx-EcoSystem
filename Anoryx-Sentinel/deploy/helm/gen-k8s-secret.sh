#!/bin/sh
# gen-k8s-secret.sh — create the Anoryx Sentinel demo prerequisites in a K8s
# namespace WITHOUT writing any secret into the repo (ADR-0027 D3 / R3).
#
# Creates, from freshly generated dev values + the canonical deploy/ scripts:
#   Secret    <release>-sentinel-env       (SENTINEL_KEY_SECRET, SENTINEL_ADMIN_TOKEN,
#                                            SESSION_SECRET, BULK_STORAGE_ACCESS_KEY,
#                                            BULK_STORAGE_SECRET_KEY)
#   ConfigMap <release>-sentinel-seed-scripts   (seed.py   <- deploy/seed/seed.py)
#   ConfigMap <release>-sentinel-worker-scripts (run_worker.py <- deploy/worker/run_worker.py)
#
# The script ConfigMaps are built from the CANONICAL compose files (zero drift).
# The bundled-Postgres password is rendered by the chart itself (dev-grade default),
# so it is NOT created here.
#
# Idempotent: re-running applies (create-or-update), never errors on existing.
#
# Usage (from the Anoryx-Sentinel directory):
#   bash deploy/helm/gen-k8s-secret.sh <namespace> [release]
#   # default release: sentinel  ->  Secret name: sentinel-sentinel-env
#
# CHANGE IN PROD: use a real secret manager (Vault / External Secrets Operator);
# these values are dev-grade and ephemeral.

set -eu

NAMESPACE="${1:-}"
RELEASE="${2:-sentinel}"

if [ -z "$NAMESPACE" ]; then
    echo "usage: $0 <namespace> [release]" >&2
    exit 2
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
DEPLOY_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
SEED_PY="$DEPLOY_DIR/seed/seed.py"
WORKER_PY="$DEPLOY_DIR/worker/run_worker.py"

FULLNAME="${RELEASE}-sentinel"
ENV_SECRET="${FULLNAME}-env"
SEED_CM="${FULLNAME}-seed-scripts"
WORKER_CM="${FULLNAME}-worker-scripts"

for f in "$SEED_PY" "$WORKER_PY"; do
    [ -f "$f" ] || { echo "gen-k8s-secret: ERROR: missing $f" >&2; exit 1; }
done

rand_hex() { openssl rand -hex "$1" 2>/dev/null || \
    python3 -c "import os,sys;sys.stdout.write(os.urandom($1).hex())" 2>/dev/null || \
    python  -c "import os,sys;sys.stdout.write(os.urandom($1).hex())"; }

# Ensure the namespace exists (idempotent).
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- env Secret (apply = create-or-update; never errors on re-run) ------------ #
kubectl create secret generic "$ENV_SECRET" -n "$NAMESPACE" \
    --from-literal=SENTINEL_KEY_SECRET="$(rand_hex 32)" \
    --from-literal=SENTINEL_ADMIN_TOKEN="$(rand_hex 32)" \
    --from-literal=SESSION_SECRET="$(rand_hex 32)" \
    --from-literal=BULK_STORAGE_ACCESS_KEY="sentinel-$(rand_hex 6)" \
    --from-literal=BULK_STORAGE_SECRET_KEY="$(rand_hex 24)" \
    --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f - >/dev/null
echo "gen-k8s-secret: Secret $ENV_SECRET applied"

# --- script ConfigMaps (from the canonical compose files — zero drift) -------- #
kubectl create configmap "$SEED_CM" -n "$NAMESPACE" \
    --from-file=seed.py="$SEED_PY" \
    --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f - >/dev/null
echo "gen-k8s-secret: ConfigMap $SEED_CM applied (from $SEED_PY)"

kubectl create configmap "$WORKER_CM" -n "$NAMESPACE" \
    --from-file=run_worker.py="$WORKER_PY" \
    --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f - >/dev/null
echo "gen-k8s-secret: ConfigMap $WORKER_CM applied (from $WORKER_PY)"

echo ""
echo "gen-k8s-secret: done. Install with:"
echo "  helm install $RELEASE deploy/helm/sentinel -n $NAMESPACE \\"
echo "    -f deploy/helm/sentinel/values.example.yaml --set envSecret=$ENV_SECRET"
