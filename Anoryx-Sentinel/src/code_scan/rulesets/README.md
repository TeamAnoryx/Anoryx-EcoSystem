# F-016 Offline Semgrep Ruleset

## Honest scope

This directory contains a **curated, pinned, offline** Semgrep ruleset for
Anoryx Sentinel's `CodeScanDetector` (F-016, ADR-0019).

v1 ships `python-security.yaml` — a hand-curated set of high-signal Python
security patterns covering:

- Command injection (`os.system`, `subprocess(shell=True)`, `os.popen`)
- Arbitrary code execution (`eval`, `exec`)
- SQL injection (string-format / f-string / `.format()` in cursor.execute)
- Unsafe deserialisation (`yaml.load` without safe Loader, `pickle.loads`)
- Weak cryptography (MD5, SHA-1, DES, `random.random` for secrets)
- Hardcoded credentials (structural kwarg patterns)
- Path traversal patterns

**v1 ships a single curated `python-security.yaml` rather than separate `p/python`, `p/security-audit`, and `p/secrets` packs; expanding to those separate packs is deferred to a dependency-update PR (ADR-0019 §13).**

## Why offline, not `p/python` registry packs

The Semgrep registry packs (`p/python`, `p/security-audit`, `p/secrets`) require
a **network round-trip** to `semgrep.dev` to fetch and materialise rules.  The
scanner runs in the hot response path and must be **hermetic**:

- No egress from the scanner subprocess (DoS and data-leak guard — ADR-0019 §5).
- No dependency on external service availability.
- Deterministic, reproducible results across environments.

Running with `--metrics=off --disable-version-check` plus a local `--config`
path (never a registry pack name or URL) ensures zero outbound network traffic.
These are the exact flags passed to every Semgrep subprocess invocation — there
is no `--offline` flag in the Semgrep CLI; `--metrics=off --disable-version-check`
is the hermetic equivalent.

## Rule freshness

Rules are updated by bumping this file in the repository — a deliberate
dependency update, not a runtime fetch.  This is an acknowledged trade-off
between rule freshness and scanner hermeticity (ADR-0019 §13 deferrals).

## Bandit

Bandit requires no vendored rules — it ships its own rule catalogue as Python
code.  The `code-scan` extra pins `bandit>=1.7,<2`.

## Adding rules

Add rules to `python-security.yaml` (or create a new YAML in this directory
and register the path in `scanners.py::SEMGREP_RULESET_PATH`).  Follow the
existing severity conventions:

| Semgrep severity | Maps to (verdict.py) |
|---|---|
| ERROR | high |
| WARNING | medium |
| INFO | low |

Never pull rules from the network at runtime.
