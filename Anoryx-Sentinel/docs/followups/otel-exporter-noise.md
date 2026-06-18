# F-010 follow-up: OTel exporter log noise when collector unreachable

## Symptom
Each request triggers `Future exception was never retrieved` with `socket.gaierror: Name or service not known` when the OTel collector hostname doesn't resolve.

## Reproduction
`docker run` the slim image without a reachable OTel collector. Send requests to `/livez`. Each one emits the exception logline.

## Why it's noise
The OTel BatchSpanProcessor queues spans. When the exporter's target is unreachable, the export future fails — but the future is never `await`ed, so Python's asyncio loop logs the warning at GC time.

## Proposed fix (defer to F-010.3 or next observability touch)
- Configure BatchSpanProcessor with shorter export timeout for faster failure surfacing
- Install a NoOp exporter when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset (instead of defaulting to localhost:4317)
- Alternative: install an asyncio exception handler that swallows DNS resolution failures from OTel exporters silently with rate-limited warnings

## Severity
Cosmetic. Functionally harmless. Affects operator first-impression in non-production deploys.

## Discovered
F-010 PR #14 smoke test (Affu, 2026-06-18). Did not block merge.
