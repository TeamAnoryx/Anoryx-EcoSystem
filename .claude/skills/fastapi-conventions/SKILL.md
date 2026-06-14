Document Anoryx Sentinel's FastAPI async conventions:
- Lifespan context manager (not @app.on_event) for startup/shutdown
- Dependency injection: asyncpg pool, auth (virtual-key lookup), OPA client — all via Depends()
- Error model: always { error_code: str, message: str, request_id: UUID } on failures
- Middleware order: request-id injection → auth → rate-limit → body parsing
- The four stable IDs are extracted in auth middleware, injected into every request context
  and every structlog log entry. Never passed manually through function args — use context vars.
- Structlog: every log line has method, path, tenant_id, team_id, duration_ms, status_code.
  No PII in logs.
- OpenTelemetry: create a span in every route handler; propagate trace context downstream.
