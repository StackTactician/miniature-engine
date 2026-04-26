from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.models import DataModel, ModelField, TrafficRecord


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


def infer_models(records: list[TrafficRecord]) -> list[DataModel]:
    field_types: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for record in records:
        body = record.response_body
        if not isinstance(body, dict):
            continue

        model_name = record.url.rstrip("/").split("/")[-1] or "root"

        for key, value in body.items():
            field_types[model_name][key].add(_infer_type(value))

    models: list[DataModel] = []
    for model_name, fields_map in field_types.items():
        fields = [
            ModelField(name=field, type="|".join(sorted(types)))
            for field, types in sorted(fields_map.items())
        ]
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
