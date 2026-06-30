"""Delta budget engine (D-005) — real-time spend-vs-budget evaluation + enforcement.

The killer-feature half on the Delta side: derive authoritative cumulative spend from the
D-003 ledger, evaluate it against configured budgets on each ledger append (event-driven),
emit advisory warnings at soft thresholds, and — when cumulative spend crosses a hard cap
— sign and publish a ``budget_limit`` policy to the O-004 distribution seam so Sentinel
F-008 blocks the scope. See ``Delta/docs/adr/0005-delta-budget-engine.md``.

Honesty boundary: Delta-leg enforcement only. The kill-switch is D-006, the allocation UI
is D-007, dashboards are D-008, and the full 3-product live block is X-003 — this package
proves the publish reaches the real O-004 seam and the signed policy is accepted by the
real Sentinel intake, not the live gateway allow→deny.
"""
