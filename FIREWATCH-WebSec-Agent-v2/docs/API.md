# API Reference

## POST `/api/v1/scans`

Create and queue an authorized assessment.

```json
{
  "target_url": "https://authorized.example/",
  "scope_acknowledged": true,
  "max_pages": 300,
  "max_depth": 8,
  "max_endpoints": 2000,
  "request_delay_ms": 150,
  "max_concurrency": 6,
  "enable_browser": true,
  "enable_api_introspection": true,
  "enable_zap": false,
  "passive_only": false,
  "respect_robots": true,
  "exclusions": ["/logout", "/delete-account"],
  "allowed_hosts": [],
  "request_headers": {},
  "auth_cookies": null,
  "authorization_profiles": []
}
```

`request_headers`, `auth_cookies`, and authorization-profile headers must be treated as secrets. They are redacted in scan-detail API responses.

## GET `/api/v1/scans`

Returns recent scan jobs.

## GET `/api/v1/scans/{id}`

Returns status, scope configuration with sensitive values redacted, and discovery/finding counts.

## GET `/api/v1/scans/{id}/events`

Returns the assessment timeline and phase progress.

## GET `/api/v1/scans/{id}/assets`

Returns the discovered asset inventory.

## GET `/api/v1/scans/{id}/findings`

Returns findings ordered by risk score.

## POST `/api/v1/scans/{id}/cancel`

Cancels a queued/running job. The running worker will observe cancellation between major phases in future releases; v2 currently prevents queued jobs from starting after cancellation.

## GET `/api/v1/scans/{id}/report?format=html`

Returns the HTML evidence report. Use `format=json` for machine-readable output.

## GET `/`

Serves the dependency-free dashboard.

## GET `/health`

Returns service status and FIREWATCH version.
