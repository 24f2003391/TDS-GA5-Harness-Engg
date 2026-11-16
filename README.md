# TDS GA5 — Harness Engineering

Deterministic FastAPI endpoint for the `agent-harness-2026-09` profile.

## Endpoints

- `GET /health` — health check
- `POST /` — classify a batch of independent cases

## Run locally

```bash
python -m pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

POST JSON to `http://localhost:8000/` with the required profile, batchId, policy, and cases.

## Deploy

The repository includes a Render Blueprint in `render.yaml`. The public submission URL is the service root URL ending in `/`.
