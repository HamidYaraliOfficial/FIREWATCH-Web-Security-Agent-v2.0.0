# Testing Guide

## Automated tests

```bash
PYTHONPATH=backend pytest -q backend/tests
```

The test suite covers:

- same-host scope enforcement and path exclusions
- deterministic security checks
- API health and scope acknowledgement
- live CLI-to-report end-to-end scanning against the included Demo Target

## Demo target

Start the intentionally weak local target:

```bash
python -m uvicorn demo_target.main:app --host 127.0.0.1 --port 8765
```

Run FIREWATCH against it:

```bash
ALLOW_PRIVATE_TARGETS=true PYTHONPATH=backend python -m app.cli http://127.0.0.1:8765/ --pages 50 --depth 4 --delay 0
```

The Demo Target is deliberately local and controlled. It exposes weak headers/cookies, a password form, a GraphQL endpoint, a CORS reflection behavior and other observations for scanner validation.

## Browser validation

Playwright is included in the backend image and can be enabled with the dashboard or CLI default. Browser navigation is constrained by the same scope policy and does not submit application forms.

## Docker validation

Docker is required to run `docker compose up --build`. The validation environment used to prepare this package did not contain the Docker CLI, so the Compose image build was not executed here.
