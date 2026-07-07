/**
 * The session cookie name, factored into its own dependency-free module so
 * `src/middleware.ts` (Edge runtime) can reference it without pulling in
 * `server-only` or `node:crypto` (used by session.ts / session-token.ts,
 * which are Node-runtime-only) into the Edge bundle.
 */
export const SESSION_COOKIE = "delta_admin_session";
