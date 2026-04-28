from app.analysis import infer_models, infer_relationships
from app.models import DataModel, ModelField, TrafficRecord


def test_infer_models_uses_resource_segment_for_id_paths() -> None:
    records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/users/1",
            response_status=200,
            response_body={"id": 1, "name": "alice"},
        ),
        TrafficRecord(
            method="GET",
            url="https://x.test/users/2",
            response_status=200,
            response_body={"id": 2, "name": "bob"},
        ),
    ]

    models = infer_models(records)

    assert len(models) == 1
    assert models[0].name == "users"
    assert {field.name for field in models[0].fields} == {"id", "name"}


def test_infer_models_handles_hex_identifier_segments() -> None:
    records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/teams/abc123def",
            response_status=200,
            response_body={"id": "abc123def", "name": "core"},
        )
    ]

    models = infer_models(records)

    assert [model.name for model in models] == ["teams"]


def test_infer_relationships_handles_camel_and_plural_id_fields() -> None:
    models = [
        DataModel(name="users", fields=[ModelField(name="id", type="integer")]),
        DataModel(name="team", fields=[ModelField(name="userId", type="integer")]),
        DataModel(name="project", fields=[ModelField(name="users_id", type="integer")]),
    ]

    relationships = infer_relationships(models)

    assert ("team", "users") in relationships
    assert ("project", "users") in relationships
