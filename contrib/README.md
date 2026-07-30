# contrib/

Ready-to-use integration artifacts for running cache-turbo in production. These
are **not** built, installed or tested by the module — import them into your own
monitoring stack and adapt as needed.

| File | What it is |
|---|---|
| [`grafana-dashboard.json`](grafana-dashboard.json) | Grafana dashboard for the module's Prometheus surface. |

## Grafana dashboard

Import `grafana-dashboard.json` in Grafana (**Dashboards → New → Import → Upload
JSON file**) and pick your Prometheus datasource. Dashboard uid is
`cache-turbo`, schema version 39.

Every panel is filtered by a `zone` template variable, so one dashboard serves
every `cache_turbo_zone` you scrape.

Panels:

- **L1 hit ratio**, **L2 hit ratio**, **Avg origin regen cost**, **Autotuned
  beta (x1000)** — headline stat tiles.
- **L1 requests/s** — hit / miss / stale.
- **L2 + origin** — l2 hit / l2 miss / refresh per second.
- **SIE serves/s** — responses served from a stale-if-error snapshot.
- **Breaker serves/s** — responses served from the circuit breaker's armed
  fallback while OPEN.
- **Origin failures/s** — origin responses the breaker recorded as failures.
- **Breaker opens/s** — CLOSED→OPEN trips.
- **Breaker state** — 0=closed, 1=open, 2=half-open.

### Prerequisites

The dashboard queries the admin endpoint's Prometheus output, so that endpoint
must be enabled and scraped:

```yaml
scrape_configs:
  - job_name: cache_turbo
    metrics_path: /_cache
    params:
      format: [prometheus]
    static_configs:
      - targets: ['nginx-host:80']
```

The endpoint's `allow`/`deny` gate applies — let your Prometheus box reach it,
keep the public out.

## See also

- [Monitoring (Prometheus + Grafana)](../README.md#monitoring-prometheus--grafana)
  — the full metric table, every counter and gauge the module exports, and
  useful PromQL.
- [Root README](../README.md) — directives, configuration and behaviour.
