# Verification Record

Date: 2026-10-05

## Static validation

- `python -m compileall -q backend/app demo_target` — passed.
- Versioned backend tests — passed (5 tests).

## End-to-end engine

A live local Demo Target was launched and scanned through the FIREWATCH CLI.

Verified path:

`CLI -> ScopePolicy -> HTTP crawler -> security checks -> API discovery -> GraphQL introspection -> TLS/metadata checks -> evidence persistence -> HTML/JSON report`

Observed result:

- Status: `completed`
- Findings: `38`
- JSON report: generated
- HTML report: generated
- Findings included CORS origin reflection, GraphQL introspection, cookie/session findings and authentication-form findings.

## End-to-end API / dashboard

A live FIREWATCH API instance was launched with the internal queue worker and a live Demo Target.

Verified:

- `POST /api/v1/scans` returned `201`.
- Scan transitioned `queued -> running -> completed`.
- Example result: 5 pages, 17 assets, 38 findings.
- `/` dashboard returned `200`.
- `/docs` returned `200`.
- Findings endpoint returned 38 findings.
- HTML report endpoint returned `200`.

## Browser mode

A second live CLI scan was run with browser discovery enabled. It completed successfully and generated reports.
