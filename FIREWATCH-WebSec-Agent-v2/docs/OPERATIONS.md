# Operations Guide

## Local development

```bash
cd backend
python -m venv .venv
# activate the venv
pip install -r requirements.txt
PYTHONPATH=. uvicorn app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/`.

## Run a direct scan

```bash
PYTHONPATH=backend ALLOW_PRIVATE_TARGETS=true python -m app.cli https://authorized.example --pages 300 --depth 8
```

## Run the local demo target

Terminal 1:

```bash
python -m uvicorn demo_target.main:app --host 127.0.0.1 --port 8765
```

Terminal 2:

```bash
PYTHONPATH=backend ALLOW_PRIVATE_TARGETS=true python -m app.cli http://127.0.0.1:8765/ --pages 50 --depth 4 --delay 0
```

## Docker

```bash
docker compose up --build
```

Then open `http://127.0.0.1:8000/`.

The `demo` and `external-worker` services are optional profiles.

## Authenticated assessments

The API accepts `request_headers`, `auth_cookies`, and optional `authorization_profiles`. Secrets are redacted from scan-detail API responses and should still be handled as credentials. For production deployments, use a protected database, encrypted transport, least-privileged accounts, and controlled access to reports.

`authorization_profiles` is an array such as:

```json
[
  {"name":"admin","headers":{"Authorization":"Bearer ..."}},
  {"name":"user","headers":{"Authorization":"Bearer ..."}}
]
```

This enables a conservative, read-only authorization comparison on sensitive-looking endpoints. A resulting finding is explicitly a **review candidate**, not proof of BOLA/BFLA.
