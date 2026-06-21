"""SSO / operator identity layer (F-014, ADR-0017).

This package adds the deferred admin-identity surface for human operators on the
admin plane ONLY (the /v1 data plane is untouched, R2):

  secret_box  — AES-256-GCM encrypt-at-rest helper for IdP secrets (D3, R6).
  audit       — SSO/operator audit emit helper (D9 honest attribution).
  idp_routes  — per-tenant IdP-config + group→role-mapping admin endpoints (D3).

STEP 3 wires per-tenant IdP config storage with secrets encrypted at rest and
the group→role mapping table. The OIDC/SAML middleware, operator-session, and the
require_admin SSO branch arrive in later steps and are NOT part of STEP 3.
"""
