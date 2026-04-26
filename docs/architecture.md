# Architecture

API Graph Mapper is a visual reconnaissance tool designed to map internal APIs and data models from observed traffic.

## High-level Flow

1. **Capture**: HTTP traffic is ingested via HAR uploads, JSON pastes, or **Playwright live capture**.
2. **Process**: The processing engine normalizes paths (e.g., `/users/123` → `/users/{id}`), deduplicates endpoints, and detects behavior patterns like pagination and authentication status.
3. **Analyze**: The analysis engine infers JSON schemas from response bodies, detects Personally Identifiable Information (PII) in model fields, and identifies relationships between models (e.g., `user_id` → `users`).
4. **Map**: The graph engine assembles these components into a directed graph of Endpoint and Model nodes.
5. **Visualize**: A React-based frontend renders the graph interactively using React Flow, with hierarchical layouts provided by Dagre.

---

## Core Components

### 1. Capture Layer
- **Static Adapters**: Ingest pre-collected traffic via JSON or HAR files.
- **Playwright Adapter**: Launches a headless Chromium instance to autonomously navigate a URL, scroll for lazy-loaded data, and intercept all XHR/Fetch API responses in real-time.

### 2. Processing Engine
- **Path Normalization**: Uses regex to identify UUIDs and numeric IDs, replacing them with placeholders to consolidate dynamic routes.
- **Security Context**: Analyzes request headers for auth tokens (`Authorization`, `Cookie`, etc.) to determine the authentication footprint of each endpoint.
- **Pattern Detection**: Identifies CRUD operations based on HTTP verbs and detects pagination signals in both query parameters and response bodies.

### 3. Analysis Engine
- **Schema Inference**: Dynamically builds a unified field map for data models, supporting union types when fields vary across different responses.
- **PII Detection**: Scans field names against sensitive data patterns to flag potential privacy risks.
- **Relationship Discovery**: Maps foreign keys (`*_id`) to inferred model names to build a structural map of the data layer.

### 4. Visualization (Frontend)
- **React Flow Engine**: Handles high-performance graph rendering and interaction.
- **Dagre Layout**: Computes a deterministic, hierarchical "Left-to-Right" layout to represent the flow from API consumers (endpoints) to data storage (models).
- **Security Overlays**: Visualizes detected risks (Unauth, IDOR, PII) using badges and conditional styling.

---

## Tech Stack

- **Backend**: Python 3.13 + FastAPI
- **Browser Automation**: Playwright (Sync API)
- **Frontend**: React + Vite + Vanilla CSS
- **Graph Logic**: `@xyflow/react` + `@dagrejs/dagre`

---

## Current Scope & Limitations

- **State**: Currently stateless; graphs are generated on-the-fly and kept in-memory.
- **Security**: Focuses on *surface-level* reconnaissance (missing auth, PII names); does not perform active exploitation.
- **Traffic**: Optimized for JSON-based REST APIs. Non-JSON payloads are currently ignored.
