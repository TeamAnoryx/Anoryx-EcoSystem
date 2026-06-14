Redis Streams event emission for Anoryx-Sentinel/src/orchestration/:
- Stream name: sentinel:events:{env} (e.g., sentinel:events:prod)
- XADD: always include event_type, tenant_id, team_id, project_id, agent_id,
  ts (ISO-8601), payload (JSON string). Conforms to contracts/events.schema.json.
- MAXLEN trimming: XADD ... MAXLEN ~ 100000 ... (approximate, prevents unbounded growth)
- Consumer group for Anoryx-AI-Orchestrator: XGROUP CREATE sentinel:events:prod anoryx-ai $ MKSTREAM
- Backpressure: check XLEN before emitting; if > 50000 → log WARNING
- Kafka migration path: wrap XADD in EventEmitter interface; swap implementation without changing callers
