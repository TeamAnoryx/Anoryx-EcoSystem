# Guided sandbox onboarding (F-025, ADR-0031)

Provision a pre-capped sandbox tenant, sign and push sample governance
policies, and make a first request through the gateway — in a handful of
commands.

> Honest scope. This is an **operator-run CLI**, not public self-serve
> signup — see [ADR-0031](../docs/adr/0031-self-serve-onboarding.md) "Scoping
> decision" for why. It is the same trust tier as `sentinel-cli` /
> `sentinel-dr`: whoever runs it needs cluster/environment access already.
> A sandbox tenant has **no governance until you push the sample policies**
> (step 2) — do that before handing out the key.

---

## 1. Provision the sandbox

```sh
sentinel-onboarding sandbox create \
  --name "acme-trial" \
  --write-templates ./acme-trial-policies
```

This creates a tenant + team + project + one virtual API key, and prints:

- the tenant/team/project/key IDs,
- the virtual API key **exactly once** — copy it now, it is never shown again,
- a ready-to-run sample `curl /v1/chat/completions` command,
- the two sample policy templates written to `./acme-trial-policies/`.

`--team-name` / `--project-name` override the defaults (`sandbox-team` /
`sandbox-project`). `--gateway-url` changes the base URL used in the printed
sample command (default `http://localhost:8000`).

## 2. Push the sample policies (do this before sharing the key)

The sandbox has **no budget or model cap** until you push policies — F-008's
signed-intake trust model means Sentinel never fabricates a policy for you;
you sign it with your own keypair.

```sh
# First time only — generate a keypair (dev/test; see ADR-0009 §11 for a
# production HSM-managed key).
sentinel-cli policy keygen --out sandbox-signing.pem --pub-out sandbox-signing-pub.pem

# Point Sentinel at the public key (env, or your deploy's secret mount):
export POLICY_SIGNING_PUBKEY_PATH=$(pwd)/sandbox-signing-pub.pem

# Sign + push both sample templates.
sentinel-cli policy push --file ./acme-trial-policies/budget-daily-cap.json --key sandbox-signing.pem
sentinel-cli policy push --file ./acme-trial-policies/model-allowlist-starter.json --key sandbox-signing.pem
```

The bundled templates:

| File | What it does |
|---|---|
| `budget-daily-cap.json` | Tenant-wide 50,000 tokens/day cap (`budget_limit`, `period: daily`, `scope: tenant`) — bounds a runaway trial script. |
| `model-allowlist-starter.json` | Restricts the tenant to `gpt-3.5-turbo` + `claude-haiku-4-5` (`model_allowlist`) — a trial should not silently route to every model a deployment happens to have provider credentials for. |

Edit the JSON before pushing if you want different limits — they're plain
files, not a compiled artifact.

## 3. Make a request

Use the `curl` command `sandbox create` printed, or reconstruct it:

```sh
curl "$GATEWAY_URL/v1/chat/completions" \
  -H "Authorization: Bearer <the key from step 1>" \
  -H "X-Anoryx-Tenant-Id: <tenant_id>" \
  -H "X-Anoryx-Team-Id: <team_id>" \
  -H "X-Anoryx-Project-Id: <project_id>" \
  -H "X-Anoryx-Agent-Id: sandbox-trial" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}'
```

**This only succeeds if the deployment has a real upstream provider
configured** (`UPSTREAM_BASE_URL` + `UPSTREAM_API_KEY`, or `ANTHROPIC_API_KEY`,
or the `AWS_*` Bedrock credentials — see the root `.env.example`). Sentinel
is a governance/inspection gateway, not a model host — there is no mock
response.

## 4. What this does and does not claim

**Does:** a real tenant + team + project + working virtual API key in one
guided step; sample governance policies using the exact, unmodified F-008
signed-intake path (no bypass, no new trust boundary); a printed, correct
sample request.

**Does not (and you must account for):** public/anonymous self-serve signup
(operator-run only); a working request without a real upstream provider
configured (no mock/echo provider exists); automatic policy enforcement
before you push the templates in step 2; a browser-based wizard (the HTTP
admin API for team/project creation doesn't exist yet — see
[docs/followups/f-025-team-project-admin-api.md](../docs/followups/f-025-team-project-admin-api.md)
for the fully-specified follow-up).
