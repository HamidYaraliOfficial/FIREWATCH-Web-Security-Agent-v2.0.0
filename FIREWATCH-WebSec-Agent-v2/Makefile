.PHONY: backend test demo docker
backend:
	PYTHONPATH=backend uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

test:
	PYTHONPATH=backend pytest -q backend/tests

demo:
	uvicorn demo_target.main:app --host 127.0.0.1 --port 8765

docker:
	docker compose up --build
