# FIREWATCH Web Security Agent v2.0.0

FIREWATCH is a scope-controlled web security assessment platform for **authorized testing**. The v2 engine expands the original scanner into an auditable assessment pipeline with asset discovery, browser observation, API inventory, evidence-backed findings, risk scoring, and HTML/JSON reporting.

## What is new in v2

- Comprehensive crawl and asset inventory
- JavaScript endpoint discovery heuristics
- Browser discovery with Playwright
- Browser request/cookie/storage inventory
- OpenAPI/Swagger discovery and basic security-declaration review
- GraphQL discovery and optional read-only introspection
- TLS version/cipher inspection
- HTTPS downgrade checks
- Security-header, cookie, CORS, caching, form and information-disclosure checks
- Conservative two-profile authorization review candidates
- Progress/event timeline
- Live web dashboard
- Single-service local UX with integrated queue worker
- Optional standalone worker and ZAP adapter architecture
- Scope acknowledgment, same-host policy, exclusions, rate limiting, robots support
- HTML + JSON evidence-oriented reports

## Safety model

FIREWATCH is intentionally non-destructive by default. It does not brute force accounts, submit arbitrary forms, delete or mutate target state, or execute target-provided commands. Active checks are limited to read-oriented requests and explicitly defined test flows such as GraphQL introspection.

Always use it only on targets for which you have explicit authorization.

## Quick start

### Local

```bash
cd backend
pip install -r requirements.txt
cd ..
PYTHONPATH=backend ALLOW_PRIVATE_TARGETS=true python -m app.cli http://127.0.0.1:8765/ --pages 50 --depth 4 --delay 0
```

### Server + dashboard

```bash
PYTHONPATH=backend ALLOW_PRIVATE_TARGETS=true uvicorn app.main:app --port 8000
```

Open `http://127.0.0.1:8000/`.

### Docker

```bash
docker compose up --build
```

Dashboard: `http://127.0.0.1:8000/`
API docs: `http://127.0.0.1:8000/docs`

## Repository

```text
backend/
  app/
    checks/          # deterministic security rules
    api_discovery.py # OpenAPI / GraphQL discovery
    authz.py         # conservative authorization comparison
    browser.py       # Playwright browser observation
    crawler.py       # same-host crawler and endpoint inventory
    orchestrator.py  # assessment pipeline
    report.py        # HTML / JSON reports
    scope.py         # target boundary enforcement
    worker.py        # optional standalone worker
frontend/
  index.html
  static/
demo_target/
docs/
```

See `docs/SECURITY_COVERAGE.md` and `docs/OPERATIONS.md` for coverage and operational guidance.
