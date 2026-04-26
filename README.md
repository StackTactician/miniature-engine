# API Graph Mapper

API Graph Mapper is a developer/security tool that captures website API traffic and turns it into an interactive graph of endpoints, schemas, and relationships.

## MVP

The MVP in this repository focuses on:

1. Capturing HTTP request/response records (ingested from capture adapters)
2. Normalizing and grouping endpoints (e.g. `/users/123` -> `/users/{id}`)
3. Inferring basic JSON schemas from responses
4. Building an in-memory graph model
5. Serving graph data over a FastAPI backend

## Project Structure

- `backend/app/main.py`: FastAPI entrypoint
- `backend/app/models.py`: Domain models for traffic, schema, and graph entities
- `backend/app/processing.py`: Normalization, deduplication, CRUD pattern detection
- `backend/app/analysis.py`: Schema inference and relationship detection
- `backend/app/graph.py`: Graph assembly utilities
- `backend/app/capture.py`: Capture adapter interfaces (mitmproxy/playwright-ready)
- `docs/architecture.md`: System architecture and phased roadmap

## Run

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open:

- API docs: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`

## Notes

- The capture layer is adapter-based so mitmproxy and Playwright integrations can be added without changing analysis logic.
- Storage is currently in-memory for MVP speed; Neo4j/PostgreSQL can be plugged in as a persistence layer in Phase 2.
