from __future__ import annotations

from abc import ABC, abstractmethod

from app.models import TrafficRecord


class TrafficCaptureAdapter(ABC):
    """Adapter contract for capture engines (mitmproxy, Playwright, etc.)."""

    @abstractmethod
    def collect(self) -> list[TrafficRecord]:
        raise NotImplementedError


class StaticCaptureAdapter(TrafficCaptureAdapter):
    """Simple adapter for development/testing using pre-collected records."""

    def __init__(self, records: list[TrafficRecord]):
        self._records = records

    def collect(self) -> list[TrafficRecord]:
        return self._records
