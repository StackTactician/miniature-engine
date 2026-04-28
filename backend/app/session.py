from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.models import TrafficRecord


@dataclass
class ProxySession:
    records: list[TrafficRecord] = field(default_factory=list)

    def add(self, record: TrafficRecord) -> None:
        self.records.append(record)

    def clear(self) -> None:
        self.records.clear()

    def count(self) -> int:
        return len(self.records)

    def host_count(self) -> int:
        return len({urlparse(r.url).netloc for r in self.records})


# Module-level singleton shared across all requests.
session = ProxySession()
