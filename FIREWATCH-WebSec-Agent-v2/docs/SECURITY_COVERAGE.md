# FIREWATCH v2 Security Coverage

FIREWATCH v2 is an **authorized, scope-controlled web application security assessment platform**. It is designed to maximize useful evidence without performing destructive exploitation, credential attacks, brute-force discovery, state-changing form submissions, or arbitrary command execution.

## Coverage baseline

The test taxonomy is mapped conceptually to OWASP Top 10:2025, OWASP Web Security Testing Guide v4.2, and OWASP API Security Top 10:2023.

### Discovery

- HTTP/HTTPS target validation
- Same-host asset inventory
- HTML link/resource discovery
- JavaScript endpoint heuristics
- robots.txt and sitemap discovery
- technology fingerprinting
- browser network/request discovery
- browser cookies and storage-key inventory
- API specification discovery
- GraphQL endpoint discovery

### Transport and response security

- HTTPS/HSTS posture
- HTTPS → HTTP downgrade redirect
- TLS protocol/cipher inspection
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- clickjacking controls
- mixed content
- server/framework disclosure
- verbose error disclosure
- sensitive-looking response caching posture

### Cookies and session

- Secure
- HttpOnly
- SameSite
- session-like cookie heuristics

### Forms and authentication

- password over HTTP
- state-changing form CSRF-token review candidate
- authentication endpoint discovery
- supplied authenticated headers/cookies

### API security

- OpenAPI/Swagger inventory
- undocumented authentication requirements in specifications
- GraphQL discovery
- optional read-only GraphQL introspection
- OPTIONS / Allow inventory
- CORS wildcard detection
- CORS arbitrary-origin reflection detection
- access-control review candidates using two explicitly supplied authorization profiles

### Evidence quality

Every finding includes:

- rule identifier
- category
- endpoint
- severity
- confidence
- risk score
- evidence summary
- remediation
- references
- deduplication key

## Deliberate non-capabilities

The default engine does not automatically:

- brute-force credentials
- submit arbitrary application state changes
- delete or modify user data
- weaponize SSRF
- execute OS commands through a target
- exploit targets beyond non-destructive verification
- scan hosts outside the configured scope

For higher-assurance penetration testing, the architecture exposes adapters for dedicated tools such as OWASP ZAP while preserving FIREWATCH scope controls.
