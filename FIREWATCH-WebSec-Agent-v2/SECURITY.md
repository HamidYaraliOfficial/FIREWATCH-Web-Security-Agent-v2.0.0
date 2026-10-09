# Security Policy

## Scope

This repository contains an authorized web assessment platform. Report security issues in FIREWATCH itself privately to the project maintainer before public disclosure.

## Safe operation

Never configure FIREWATCH with a target that you are not authorized to assess.

The default configuration rejects private/reserved IP targets. To run the included local demo, explicitly enable:

```text
ALLOW_PRIVATE_TARGETS=true
```

This setting should not be enabled on a production worker without an explicit network security policy.

## Threat model

Treat the target application, HTTP responses, JavaScript and report artifacts as untrusted input. Do not execute arbitrary JavaScript from target content inside the backend process.

Browser discovery runs in a sandboxed/isolated browser context and should be hosted in a dedicated worker network in production.
