from __future__ import annotations

from collections import defaultdict
import re
from typing import Any
from urllib.parse import urlparse

from app.models import DataModel, ModelField, TrafficRecord

_ID_LIKE_SEGMENT = re.compile(r"^\d+$|^[0-9a-fA-F]{8,}$")


def _infer_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _infer_model_name(url: str) -> str:
    path_parts = [part for part in urlparse(url).path.split("/") if part]
    if not path_parts:
        return "root"

    last = path_parts[-1]
    if _ID_LIKE_SEGMENT.match(last) and len(path_parts) > 1:
        return path_parts[-2]

    return last


def infer_models(records: list[TrafficRecord]) -> list[DataModel]:
    field_types: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for record in records:
        body = record.response_body
        if not isinstance(body, dict):
            continue

        model_name = _infer_model_name(record.url)

        for key, value in body.items():
            field_types[model_name][key].add(_infer_type(value))

    models: list[DataModel] = []
    pii_keywords = {"email", "password", "ssn", "dob", "phone", "address", "credit_card", "token", "secret"}

    for model_name, fields_map in field_types.items():
        fields = []
        for field, types in sorted(fields_map.items()):
            is_pii = any(kw in field.lower() for kw in pii_keywords)
            fields.append(
                ModelField(name=field, type="|".join(sorted(types)), is_pii=is_pii)
            )
        models.append(DataModel(name=model_name, fields=fields))

    return sorted(models, key=lambda m: m.name)


def infer_relationships(models: list[DataModel]) -> list[tuple[str, str]]:
    model_names = {m.name for m in models}
    relationships: set[tuple[str, str]] = set()

    for model in models:
        for field in model.fields:
            if field.name.endswith("_id"):
                candidate = field.name[:-3]
                if candidate in model_names:
                    relationships.add((model.name, candidate))

    return sorted(relationships)
