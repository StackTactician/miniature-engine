# Miniature Engine

An experimental engine for API endpoint discovery, static JavaScript analysis, and specification extraction.

> **Status:** Work in progress / early development. Not fully tested against production environments.

## Overview

Miniature Engine explores web applications to map candidate API endpoints and schemas:

- **Spider & Harvester:** Collects frontend scripts and framework manifests (Next.js, Nuxt, Webpack).
- **Static Analyzer:** Inspects JavaScript bundles and source maps to identify route patterns and client configurations.
- **API Prober:** Checks endpoint availability via `OPTIONS`/`HEAD` requests, discovers exposed OpenAPI/Swagger documentation, and validates GraphQL endpoints.

## Requirements

- Python 3.10+
- `httpx`
- `aiolimiter`
- `graphql-core`
- `beautifulsoup4`

## Running Tests

```bash
python3 -m unittest discover tests/ -v
```

## License

MIT
