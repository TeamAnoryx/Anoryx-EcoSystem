# R-019 Security Audit — Rendly Granular Data-Exposure Seam

Verdict: **CLEAN** (no High/Critical). Independent security-auditor pass on branch
`claude/rendly/R-019-privacy-exposure` (PR TBD). R-019 is the one seam in the
R-012/R-016/R-017/R-018 lineage whose entire purpose is information non-disclosure
— unlike its purely-computational siblings, an inverted exposure check here would
be a direct confidentiality breach rather than a functional bug, so this short note
is recorded even though (like R-012/R-016/R-017/R-018) the module introduces no I/O,
persistence, or network surface and would not otherwise warrant a dedicated audit
doc under this codebase's existing precedent.

Scope reviewed: `src/rendly/privacy.py` (`PrivacyField`, `PrivacySettings` +
`bind_privacy_settings`, `ExposedProfileView`, `reveal`), `tests/domain/
test_privacy.py`, `docs/adr/0019-rendly-privacy-exposure-seam.md`. Confirmed no
import of `rendly.privacy` anywhere outside its own test file (not wired into any
router, WebSocket handler, or persistence layer).

## Invariants actively attacked and NOT broken

- **Fail-closed default.** `reveal()` derives `granted = set(settings.granted_fields)
  if settings is not None else set()` — traced every branch of the five-field
  `ExposedProfileView` construction: each field is `<value> if PrivacyField.X in
  granted else None`, a positive membership test only, never inverted, never an
  `or`-in-place-of-`and`. `settings=None`, an empty `granted_fields`, and a
  single-field grant were each traced independently; none can produce a non-`None`
  value for a field whose `PrivacyField` is absent from `granted`.
- **Cross-user leakage.** Every one of `settings` / `intent_profile` / `career_goal`,
  when supplied, is passed through `_check_owner` (both `user_id` AND `tenant_id`
  compared) before contributing any data; a mismatch raises rather than silently
  dropping or substituting. Verified both mismatch axes (different `user_id`;
  same `user_id`, different `tenant_id`).
- **No cross-field leakage.** Each of the five `PrivacyField` values maps to
  exactly one `ExposedProfileView` field, with no shared condition that could let
  granting one field expose another.
- **No withheld-ness signal.** A field that is `None` because it was never granted
  is structurally indistinguishable from one that is `None` because the source
  record has nothing to show (both hit the same `else None` branch) — a viewer
  cannot infer "this field exists but is hidden" vs. "this field was never set."

## Low findings — accepted, non-gating

1. **No per-viewer differentiation (by design, disclosed in ADR-0019 Fork C).**
   The same `ExposedProfileView` results regardless of who is asking — there is no
   "who is this viewer to the subject" relationship concept in Rendly's pure-domain
   package to key a per-counterparty grant against. Not a defect: an honestly
   disclosed scope boundary, not a silent gap. A future task that wants
   per-counterparty exposure owns modeling that relationship first.

## Gate

CLEAN — no High/Critical. Cleared for merge. The fail-closed default and the
per-argument provenance guards were independently traced line-by-line, not
inferred from docstrings or tests alone.
