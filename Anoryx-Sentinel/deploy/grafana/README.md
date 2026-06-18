# Sentinel Grafana Dashboard — Import Guide

## What this dashboard covers

`sentinel-dashboard.json` is a single importable Grafana 10+ dashboard for the
Anoryx Sentinel AI gateway. It covers all metrics defined in ADR-0011 §5:

- Traffic: requests/sec by provider, p95 latency by route, error rate by status class
- Rate limiting: decisions by outcome (admitted / rate_limited_key / rate_limited_team / rate_limited_tenant / rate_limited_degraded)
- Data protection: PII blocks rate, policy violations by policy type
- LLM judge: invocations by preset and outcome, p95 judge latency by preset
- Shadow-AI and classifier: outbound detections, classifier degraded events
- Infrastructure: Redis health (stat panel, green=healthy / red=degraded), audit-write failures by component

Default time range: last 1 hour, auto-refresh every 30 seconds.

---

## Prerequisites

- Grafana 10.0.0 or later.
- A Prometheus datasource already configured in Grafana that scrapes the Sentinel
  gateway `/metrics` endpoint (see Prometheus scrape note below).

---

## Import steps

1. In Grafana, navigate to **Dashboards > Import** (or use the **+** menu and
   select **Import dashboard**).
2. Click **Upload JSON file** and select `sentinel-dashboard.json`, or paste the
   JSON content into the text area and click **Load**.
3. On the import confirmation screen, Grafana will prompt for the **Prometheus**
   datasource. Select the datasource that scrapes the Sentinel gateway.
4. Click **Import**.

The dashboard opens immediately. If no data appears, verify the Prometheus
datasource is correctly configured and the gateway `/metrics` endpoint is
reachable from your Prometheus server.

---

## Prometheus scrape configuration

The gateway exposes `GET /metrics` in Prometheus text exposition format on the
same port as the API. The endpoint is unauthenticated by design for scrape
simplicity.

Minimal scrape job for `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "anoryx-sentinel"
    static_configs:
      - targets: ["<gateway-host>:<gateway-port>"]
    metrics_path: /metrics
    scheme: http
```

**Production hardening required.** The `/metrics` path MUST be firewalled at the
load-balancer or ingress layer so that it is not reachable from the public
internet. Failure to do so exposes internal cardinality data (error rates, queue
depths, and — when per-tenant metrics are enabled — tenant IDs) to
unauthenticated callers. Restrict `/metrics` to the internal Prometheus scrape
CIDR only, or expose it on a separate internal port protected by a network policy.

---

## Template variables

The dashboard ships with three template variables:

| Variable     | Source                                                    | Purpose                          |
|--------------|-----------------------------------------------------------|----------------------------------|
| `datasource` | Prometheus datasource picker                              | Selects the Prometheus datasource at import time |
| `provider`   | `label_values(sentinel_requests_total, provider)`         | Filter panels to one or more AI providers |
| `route`      | `label_values(sentinel_request_duration_seconds_bucket, route)` | Filter latency panels to specific routes |

Both `provider` and `route` default to **All** (multi-select).

### Per-tenant metrics (tenant_id variable)

A `tenant_id` template variable is only meaningful when
`ENABLE_PER_TENANT_METRICS=true` is set on the gateway. With that flag enabled,
`sentinel_requests_total` and `sentinel_rate_limit_decisions_total` carry a
`tenant_id` label (server-resolved; never sourced from a client header). To add
the variable:

1. Open the dashboard in edit mode.
2. Go to **Settings > Variables > New variable**.
3. Set type to **Query**, name to `tenant_id`, label to **Tenant**.
4. Set the query to `label_values(sentinel_requests_total, tenant_id)`.
5. Enable **Include All option** and set **All value** to `.*`.
6. Add `tenant_id=~"$tenant_id"` to the relevant panel queries.

Enabling per-tenant metrics increases Prometheus storage cost linearly with
tenant count. Leave `ENABLE_PER_TENANT_METRICS` disabled (the default) unless
per-tenant granularity is operationally required.

---

## Honest language note

Panel titles use accurate operational language: "rate", "detections",
"degraded events". No panel claims detection rates are exhaustive or that the
gateway blocks all attack classes.
