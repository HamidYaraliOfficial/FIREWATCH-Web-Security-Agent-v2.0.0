# FIREWATCH v2 Architecture

```text
Browser / CLI / API client
            |
            v
      FastAPI Control Plane
            |
        Scan Queue
            |
            v
    Scan Orchestrator
      /     |      \
     v      v       v
  Scope  Discovery  Policy
          |\
          | +-- Crawler / JS endpoint extraction
          | +-- Browser / Playwright
          | +-- API / OpenAPI / GraphQL
          | +-- TLS / redirect / metadata
          |
          v
    Deterministic Check Engine
          |
      Evidence + Dedup
          |
      Risk / Confidence
          |
      PostgreSQL/SQLite
          |
     HTML + JSON Reports
          |
      Live Dashboard
```

## Design principles

1. Scope policy is enforced before requests.
2. Every check emits structured evidence.
3. Findings are deduplicated by scan, rule and endpoint evidence.
4. Secrets are redacted from scan-detail responses.
5. Browser navigation is constrained to approved hosts.
6. Active checks remain read-oriented and non-destructive.
7. Tool adapters are isolated from the deterministic core.
