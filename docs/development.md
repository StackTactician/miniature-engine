# Miniature Engine Development Guide

This guide covers local setup, testing, coding workflows, and extension patterns.

---

## 1. Prerequisites

- Python 3.13+
- Node.js 18+ / npm
- Playwright browser dependencies (for live capture)

---

## 2. Local setup

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 3. Test and validation commands

### Backend tests

```bash
cd backend
pytest -q
```

### Frontend production build

```bash
cd frontend
node ./node_modules/vite/bin/vite.js build
```

---

## 4. Backend extension patterns

### Add a new API route

1. Define request/response models in `app/models.py`.
2. Implement domain logic in a dedicated module (e.g., `app/diff.py` style).
3. Wire route in `app/main.py`.
4. Add tests in `backend/tests/`.

### Add a new capture adapter

1. Implement `TrafficCaptureAdapter` interface (`app/capture.py`).
2. Return normalized `TrafficRecord` instances.
3. Integrate route/worker path in `app/main.py`.

### Add new analysis heuristics

1. Extend `app/analysis.py` and/or `app/processing.py`.
2. Preserve deterministic behavior where possible.
3. Add targeted tests with focused fixtures.

---

## 5. Frontend extension patterns

### Add backend integration

1. Create/extend helper in `src/api.js`.
2. Consume in `App.jsx` or feature component.
3. Keep error surfaces user-readable.

### Add graph UI behavior

1. Transform backend payload in `src/layout.js`.
2. Add node/edge metadata rendering in components.
3. Keep graph state deterministic and serializable.

---

## 6. Suggested contribution checklist

- [ ] Tests updated/added for behavior changes.
- [ ] Docs updated (`README`, `docs/api.md`, feature matrix).
- [ ] API contracts stable and explicit.
- [ ] Error messages actionable for users.
- [ ] No unrelated formatting/noise changes.

---

## 7. Known development caveats

- Live capture only includes JSON XHR/fetch traffic.
- Some websites require user interactions beyond initial load/scroll.
- WebSocket stream currently provides progress + final graph (not incremental node streaming).

