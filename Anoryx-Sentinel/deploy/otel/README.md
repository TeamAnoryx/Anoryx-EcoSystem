# OpenTelemetry Collector — Anoryx Sentinel

F-010 bundles an [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
as the **interop layer** between Sentinel and your observability backend
(ADR-0012 §5, "OTel export = β"). Sentinel exports OTLP spans to the collector;
the collector exports onward to whatever backend you configure.

## Default behavior (no backend)

Out of the box `collector-config.yaml` exports to the **`debug`** exporter only —
received telemetry is written to the collector's stdout (`docker compose logs
otel-collector`). This proves the pipeline works end-to-end **without** committing
you to any vendor. Nothing leaves the box until you add a backend exporter.

## How Sentinel reaches the collector

The gateway exports OTLP/gRPC when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (it is
unset → no export → in-process no-op, per ADR-0012 §5 / R1 Deviation 1):

| Orchestrator | Endpoint |
|---|---|
| Docker Compose | `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317` (preset on `sentinel-app`) |
| Kubernetes (Helm) | `http://<release>-otel-collector:4317` (preset when `otelCollector.enabled=true`) |

## Wiring a backend

Edit `collector-config.yaml`: (1) declare an exporter, (2) add it to the relevant
pipeline's `exporters:` list. Examples are pre-written (commented) in the file.

### Jaeger (all-in-one, local)
```yaml
exporters:
  otlp/jaeger:
    endpoint: jaeger:4317
    tls: { insecure: true }
service:
  pipelines:
    traces:
      exporters: [debug, otlp/jaeger]
```

### Grafana Tempo
```yaml
exporters:
  otlp/tempo:
    endpoint: tempo:4317
    tls: { insecure: true }
```

### Honeycomb
```yaml
exporters:
  otlp/honeycomb:
    endpoint: api.honeycomb.io:443
    headers: { "x-honeycomb-team": "${env:HONEYCOMB_API_KEY}" }
```

### Datadog (requires the contrib distro — already used here)
```yaml
exporters:
  datadog:
    api: { key: "${env:DD_API_KEY}", site: "datadoghq.com" }
```

After editing, restart the collector: `docker compose restart otel-collector`
(or `kubectl rollout restart deploy/<release>-otel-collector`).

## Diagnostics

The collector exposes operational extensions: `health_check` (`:13133`),
`pprof` (`:1777`), and `zpages` (`:55679/debug/tracez`).
