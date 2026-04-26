from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from app.models import EndpointSummary, TrafficRecord

_ID_SEGMENT = re.compile(r"^\d+$|^[0-9a-fA-F]{8,}$")


METHOD_TO_OPERATION = {
    "POST": "create",
    "GET": "read",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}


def normalize_path(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    normalized: list[str] = []
    for part in parts:
        if _ID_SEGMENT.match(part):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)


def detect_pagination(record: TrafficRecord) -> bool:
    parsed = urlparse(record.url)
    query = parse_qs(parsed.query)
    pagination_params = {"page", "limit", "offset", "cursor", "per_page"}

    if pagination_params.intersection(query.keys()):
        return True

    if isinstance(record.response_body, dict):
        keys = set(record.response_body.keys())
        if {"next", "previous"}.intersection(keys) or "total" in keys:
            return True

    return False


def summarize_endpoints(records: list[TrafficRecord]) -> list[EndpointSummary]:
    seen: set[tuple[str, str]] = set()
    summaries: list[EndpointSummary] = []

    for record in records:
        parsed = urlparse(record.url)
        raw_path = parsed.path or "/"
        normalized = normalize_path(raw_path)
        method = record.method.upper()
        key = (method, normalized)
        if key in seen:
            continue

        seen.add(key)
        summaries.append(
            EndpointSummary(
                method=method,
                raw_path=raw_path,
                normalized_path=normalized,
                operation=METHOD_TO_OPERATION.get(method, "other"),
                has_pagination=detect_pagination(record),
            )
        )

    return summaries
