# Metrics Guide

This document describes the Prometheus metrics exposed by LDAP Auth RS and how to use them for monitoring and alerting.

## Endpoint

Metrics are exposed on:

- `GET /metrics`

Example:

```bash
curl -s http://localhost:8080/metrics
```

## Metric Types

The service exposes:

- HTTP metrics from `axum-prometheus`
- LDAP/Auth/Redis custom metrics from `src/metrics.rs`

## Custom Metric Catalog

### Authentication and LDAP

- `ldap_auth_attempts_total{organization, result}`
  - Counter for authentication attempts
  - `result` is `success` or `failure`

- `ldap_bind_operations_total{organization, result}`
  - Counter for LDAP bind operations
  - `result` is `success` or `failure`

### API Operation Counters

- `ldap_user_operations_total{organization, operation, result}`
  - Counter for user operations (create, update, delete, etc.)

- `ldap_group_operations_total{organization, operation, result}`
  - Counter for group operations (create, update, delete, membership changes)

### Redis Performance

- `redis_operation_duration_seconds{operation, result}`
  - Histogram for Redis operation latency in seconds
  - Buckets: `0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0`

### Entity Count Gauges

- `ldap_organizations_count`
  - Gauge for total number of tracked organizations

- `ldap_users_count{organization}`
  - Gauge for current number of users in an organization

- `ldap_groups_count{organization}`
  - Gauge for current number of groups in an organization

## How Count Gauges Are Updated

Count gauges are updated by the Redis DB service on create/delete flows:

- User create/delete updates `ldap_users_count{organization}`
- Group create/delete updates `ldap_groups_count{organization}`
- Organizations are tracked in Redis and reflected in `ldap_organizations_count`

## HTTP Metrics

HTTP metrics are provided by `axum-prometheus`. Common names include:

- `http_requests_total`
- `http_requests_duration_seconds`
- `axum_http_requests_pending`

Exact names can vary by crate version and configuration.

## Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'ldap-auth-rs'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

## Useful PromQL Queries

### Request Rate

```promql
rate(http_requests_total[5m])
```

### Error Rate (5xx)

```promql
rate(http_requests_total{status=~"5.."}[5m])
```

### P95 Latency

```promql
histogram_quantile(0.95, rate(http_requests_duration_seconds_bucket[5m]))
```

### Auth Failure Rate

```promql
rate(ldap_auth_attempts_total{result="failure"}[5m])
```

### LDAP Bind Success Rate

```promql
sum(rate(ldap_bind_operations_total{result="success"}[5m]))
/
sum(rate(ldap_bind_operations_total[5m]))
```

### Users Per Organization

```promql
ldap_users_count
```

### Groups Per Organization

```promql
ldap_groups_count
```

### Total Organizations

```promql
ldap_organizations_count
```

## Alert Ideas

- High authentication failure rate
- Increasing p95 request latency
- Sudden drop in `ldap_users_count` for a critical organization
- Spike in failed Redis operations by `result="failure"`

## Notes

- Custom metrics are lazily initialized and appear after first use.
- Metric names with the `ldap_` prefix are LDAP-domain custom metrics.
