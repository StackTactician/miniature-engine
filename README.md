# API Graph Mapper

A developer/security tool that captures website API traffic and turns it into an interactive graph of endpoints, schemas, and relationships.

## Project Structure

```
backend/          FastAPI API server
  app/
    main.py       Entrypoint + CORS config
    models.py     Domain models (TrafficRecord, GraphNode, etc.)
    processing.py Path normalization, deduplication, CRUD detection
    analysis.py   JSON schema inference and relationship detection
    graph.py      Graph assembly
    capture.py    Capture adapter interface (mitmproxy/Playwright-ready)

frontend/         React + Vite UI
  src/
    api.js        Fetch wrapper for /graph/build
    harParser.js  HAR file -> TrafficRecord[] converter
    layout.js     Dagre LR layout + API payload transform
    components/
      InputPanel.jsx   Left sidebar — JSON paste or HAR file upload
      GraphCanvas.jsx  Interactive React Flow canvas
      DetailPanel.jsx  Node detail slide-in panel
      StatsBar.jsx     Live endpoint/model/edge counts
      nodes/
        EndpointNode.jsx  Color-coded by HTTP method
        ModelNode.jsx     Purple accent, field count badge

docs/architecture.md  System design and roadmap
```

## Running

Both services must be running at the same time. Open two terminals.

### Backend

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Runs at `http://localhost:8000`. Interactive API docs at `http://localhost:8000/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Runs at `http://localhost:5173`. Open this in your browser.

## Usage

1. Open `http://localhost:5173`
2. In the left sidebar, choose **JSON Records** or **HAR File**
   - **JSON**: paste a `TrafficRecord[]` array, or click **Load example** for sample data
   - **HAR**: drag and drop a `.har` export from Chrome DevTools (Network tab → right-click → Save all as HAR)
3. Click **Build Graph**
4. Click any node to open the detail panel

## Notes

- The capture layer is adapter-based — mitmproxy and Playwright integrations can be added without touching the analysis logic.
- Storage is in-memory for MVP speed; Neo4j/PostgreSQL can be plugged in as a persistence layer in Phase 2.
