"""Delta kill-switch (D-006) — instantaneous emergency brake for unauthorized/anomalous
AI agent transactions.

See ``Delta/docs/adr/0006-delta-kill-switch.md``. Independent of, and complementary to,
the D-005 budget engine: D-005 enforces cumulative spend-vs-cap; D-006 reacts to a SINGLE
offending transaction (an unauthorized agent identity, or an anomalously large single
cost) without waiting for any period accumulation. Both publish `budget_limit` policies
to the same O-004 seam under their OWN, independent `policy_id`, so neither weakens the
other.
"""

from __future__ import annotations
