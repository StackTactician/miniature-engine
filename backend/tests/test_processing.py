from app.models import TrafficRecord
from app.processing import normalize_path, summarize_endpoints


def test_normalize_path_ids() -> None:
    assert normalize_path("/users/123/orders/abc123def") == "/users/{id}/orders/{id}"


def test_summarize_deduplicates() -> None:
    records = [
        TrafficRecord(method="GET", url="https://x.test/users/1", response_status=200, response_body={"id": 1}),
        TrafficRecord(method="GET", url="https://x.test/users/2", response_status=200, response_body={"id": 2}),
    ]
    result = summarize_endpoints(records)
    assert len(result) == 1
    assert result[0].normalized_path == "/users/{id}"
