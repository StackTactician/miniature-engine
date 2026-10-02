"""
Schema Inference Engine for OpenAPI 3.1.0 (JSON Schema 2020-12 alignment).
Pure Python 3.10+ implementation with zero external dependencies and no C-extensions.
"""

import copy
import datetime
import ipaddress
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple


def purge_legacy_nullable(obj: Any) -> Any:
    """
    Recursively purges legacy OpenAPI 3.0 `nullable: true` from schema trees,
    converting it strictly to OpenAPI 3.1 / JSON Schema 2020-12 type arrays (e.g. type: ["string", "null"]).
    """
    if isinstance(obj, dict):
        is_nullable_true = obj.pop("nullable", None) is True
        if is_nullable_true:
            t = obj.get("type")
            if isinstance(t, str):
                if t != "null":
                    obj["type"] = [t, "null"]
            elif isinstance(t, list):
                if "null" not in t:
                    obj["type"] = list(t) + ["null"]
            elif "anyOf" in obj and isinstance(obj["anyOf"], list):
                has_null_branch = any(
                    isinstance(b, dict) and b.get("type") == "null"
                    for b in obj["anyOf"]
                )
                if not has_null_branch:
                    obj["anyOf"].append({"type": "null"})
            elif "oneOf" in obj and isinstance(obj["oneOf"], list):
                has_null_branch = any(
                    isinstance(b, dict) and b.get("type") == "null"
                    for b in obj["oneOf"]
                )
                if not has_null_branch:
                    obj["oneOf"].append({"type": "null"})
            else:
                obj["type"] = ["string", "null"]
        for k in list(obj.keys()):
            obj[k] = purge_legacy_nullable(obj[k])
        return obj
    elif isinstance(obj, list):
        return [purge_legacy_nullable(item) for item in obj]
    return obj


class OpenAPISchemaInferrer:
    """
    Infers OpenAPI 3.1.0 / JSON Schema 2020-12 compliant schemas from raw sample data
    and merges schemas across multiple observations.
    """

    def __init__(self, max_depth: int = 30) -> None:
        self.max_depth = max_depth

    # RFC 4122 / general UUID regex
    _UUID_RE = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    # ISO 8601 date YYYY-MM-DD
    _DATE_RE = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$")
    # ISO 8601 date-time with time component and optional offset/Z
    _DATETIME_RE = re.compile(
        r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[Tt ]\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$"
    )
    # Standard email regex
    _EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")
    # URI regex
    _URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/$.?#].[^\s]*$")

    def infer(
        self,
        data: Any,
        current_depth: int = 0,
        seen: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """
        Infers JSON Schema 2020-12 / OpenAPI 3.1.0 schema for a Python object.
        Supported types: null, boolean, integer, number, string, array, object.
        Guarded against stack overflow via max_depth and circular reference detection.
        """
        if data is None:
            return {"type": "null"}

        # CRITICAL: In Python, bool subclasses int. Must check bool BEFORE int!
        if isinstance(data, bool):
            return {"type": "boolean"}

        if isinstance(data, int):
            return {"type": "integer"}

        if isinstance(data, float):
            return {"type": "number"}

        if isinstance(data, (bytes, bytearray)):
            return {"type": "string", "format": "binary"}

        if isinstance(data, datetime.datetime):
            return {"type": "string", "format": "date-time"}

        if isinstance(data, datetime.date):
            return {"type": "string", "format": "date"}

        if isinstance(data, str):
            clean_str = data.encode("utf-8", errors="replace").decode("utf-8")
            fmt = self.infer_string_format(clean_str)
            if fmt:
                return {"type": "string", "format": fmt}
            return {"type": "string"}

        # Recursion & cycle guard for compound structures
        if isinstance(data, (dict, list, tuple, set, frozenset)):
            if seen is None:
                seen = set()
            obj_id = id(data)
            if obj_id in seen:
                if isinstance(data, dict):
                    return {"type": "object", "description": "[Circular Reference]"}
                return {"type": "array", "description": "[Circular Reference]"}

            if current_depth >= self.max_depth:
                if isinstance(data, dict):
                    return {"type": "object", "description": "[Truncated: max depth reached]"}
                return {"type": "array", "description": "[Truncated: max depth reached]"}

            seen = set(seen)
            seen.add(obj_id)

            if isinstance(data, (list, tuple, set, frozenset)):
                data_list = list(data)
                if not data_list:
                    return {"type": "array"}
                item_schema = self.infer(data_list[0], current_depth=current_depth + 1, seen=seen)
                # Sample up to first 30 items for performance and stack safety
                for item in data_list[1:30]:
                    item_schema = self.merge(
                        item_schema,
                        self.infer(item, current_depth=current_depth + 1, seen=seen),
                        current_depth=current_depth + 1,
                    )
                return {"type": "array", "items": item_schema}

            if isinstance(data, dict):
                properties: Dict[str, Any] = {}
                try:
                    items_list = list(data.items())
                except Exception:
                    items_list = []
                for k, v in items_list:
                    safe_k = str(k).encode("utf-8", errors="replace").decode("utf-8")
                    properties[safe_k] = self.infer(v, current_depth=current_depth + 1, seen=seen)
                schema: Dict[str, Any] = {
                    "type": "object",
                    "properties": properties,
                }
                if properties:
                    schema["required"] = sorted(list(properties.keys()))
                return schema

        # Fallback for unrecognized types (Decimal, UUID, etc.)
        try:
            import decimal
            if isinstance(data, decimal.Decimal):
                return {"type": "number"}
        except ImportError:
            pass
        try:
            import uuid
            if isinstance(data, uuid.UUID):
                return {"type": "string", "format": "uuid"}
        except ImportError:
            pass

        return {"type": "string"}

    # Method alias for spec compliance and test compatibility
    infer_schema = infer

    def infer_from_samples(self, samples: List[Any]) -> Dict[str, Any]:
        """
        Infers schema by merging observations across a list of sample values.
        """
        if not samples:
            return {}
        accum = self.infer(samples[0])
        for sample in samples[1:]:
            accum = self.merge(accum, self.infer(sample))
        return accum

    def infer_string_format(self, value: str) -> Optional[str]:
        """
        Detects string formats: uuid, date, date-time, email, ipv4, uri.
        """
        if not isinstance(value, str) or not value:
            return None

        # 1. UUID
        if len(value) == 36 and self._UUID_RE.match(value):
            return "uuid"

        # 2. Date-time (checked before date so date-time strings aren't truncated)
        if self._DATETIME_RE.match(value):
            # Validate ISO date-time
            try:
                norm_val = value.replace("Z", "+00:00").replace("z", "+00:00")
                datetime.datetime.fromisoformat(norm_val)
                return "date-time"
            except (ValueError, TypeError):
                pass

        # 3. Date (YYYY-MM-DD)
        if self._DATE_RE.match(value):
            try:
                datetime.date.fromisoformat(value)
                return "date"
            except (ValueError, TypeError):
                pass

        # 4. Email
        if "@" in value and self._EMAIL_RE.match(value):
            return "email"

        # 5. IPv4
        if value.count(".") == 3:
            try:
                ipaddress.IPv4Address(value)
                return "ipv4"
            except (ValueError, ipaddress.AddressValueError):
                pass

        # 6. URI
        if "://" in value and self._URI_RE.match(value):
            try:
                parsed = urllib.parse.urlsplit(value)
                if parsed.scheme in ("http", "https", "ftp", "ftps", "ws", "wss", "sftp") and parsed.netloc:
                    return "uri"
            except Exception:
                pass

        return None

    def merge(
        self,
        schema1: Dict[str, Any],
        schema2: Dict[str, Any],
        current_depth: int = 0,
        seen: Optional[Set[Tuple[int, int]]] = None,
    ) -> Dict[str, Any]:
        """
        Combines schemas from multiple observations:
        - Union object properties
        - Intersect required fields
        - OpenAPI 3.1 nullability using type: ["string", "null"] (NEVER nullable: true)
        - Widen integer + number to number
        - Polymorphic anyOf fallback
        Guarded against stack overflow via max_depth and cycle detection.
        """
        if not schema1 and not schema2:
            return {}
        if not schema1:
            return self._normalize_schema(schema2)
        if not schema2:
            return self._normalize_schema(schema1)

        if current_depth >= self.max_depth:
            return copy.deepcopy(schema1)

        if seen is None:
            seen = set()
        pair = (id(schema1), id(schema2))
        if pair in seen:
            return copy.deepcopy(schema1)
        seen = set(seen)
        seen.add(pair)

        s1 = self._normalize_schema(schema1)
        s2 = self._normalize_schema(schema2)

        if s1 == s2:
            return copy.deepcopy(s1)

        # Handle anyOf if either schema is already polymorphic
        candidates1 = s1["anyOf"] if "anyOf" in s1 else [s1]
        candidates2 = s2["anyOf"] if "anyOf" in s2 else [s2]

        merged_list: List[Dict[str, Any]] = [copy.deepcopy(c) for c in candidates1]

        for c2 in candidates2:
            merged = False
            for idx, c1 in enumerate(merged_list):
                if self._can_merge_without_anyof(c1, c2):
                    merged_list[idx] = self._merge_direct(
                        c1, c2, current_depth=current_depth, seen=seen
                    )
                    merged = True
                    break
            if not merged:
                merged_list.append(copy.deepcopy(c2))

        # Deduplicate
        unique_list: List[Dict[str, Any]] = []
        for s in merged_list:
            if s not in unique_list:
                unique_list.append(s)

        if len(unique_list) == 1:
            return unique_list[0]
        return {"anyOf": unique_list}

    # Method alias for spec compliance and test compatibility
    merge_schemas = merge

    def _normalize_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes a schema recursively, converting legacy nullable: true to OpenAPI 3.1 type arrays.
        """
        return purge_legacy_nullable(copy.deepcopy(schema))

    def _get_types(self, schema: Dict[str, Any]) -> List[str]:
        t = schema.get("type")
        if isinstance(t, str):
            return [t]
        if isinstance(t, list):
            return list(t)
        return []

    def _can_merge_without_anyof(self, s1: Dict[str, Any], s2: Dict[str, Any]) -> bool:
        """
        Checks if two schemas can be unified without creating an anyOf branch.
        """
        if s1 == s2:
            return True

        types1 = self._get_types(s1)
        types2 = self._get_types(s2)

        # Pure null merging into any schema
        if types1 == ["null"] or types2 == ["null"]:
            return True

        non_null1 = [t for t in types1 if t != "null"]
        non_null2 = [t for t in types2 if t != "null"]

        if not non_null1 or not non_null2:
            return True

        if len(non_null1) == 1 and len(non_null2) == 1:
            k1, k2 = non_null1[0], non_null2[0]
            if k1 == k2:
                return True
            # Widen integer + number to number
            if {k1, k2} == {"integer", "number"}:
                return True

        return False

    def _merge_direct(
        self,
        s1: Dict[str, Any],
        s2: Dict[str, Any],
        current_depth: int = 0,
        seen: Optional[Set[Tuple[int, int]]] = None,
    ) -> Dict[str, Any]:
        """
        Directly merges two compatible schemas into a single schema.
        """
        types1 = self._get_types(s1)
        types2 = self._get_types(s2)

        has_null = ("null" in types1) or ("null" in types2)
        non_null1 = [t for t in types1 if t != "null"]
        non_null2 = [t for t in types2 if t != "null"]

        # Case 1: Both pure null
        if not non_null1 and not non_null2:
            return {"type": "null"}

        # Case 2: One is pure null, the other is non-null
        if not non_null1:
            res = copy.deepcopy(s2)
            cur_types = self._get_types(res)
            res_types = [t for t in cur_types if t != "null"] + ["null"]
            res["type"] = res_types if len(res_types) > 1 else res_types[0]
            return res

        if not non_null2:
            res = copy.deepcopy(s1)
            cur_types = self._get_types(res)
            res_types = [t for t in cur_types if t != "null"] + ["null"]
            res["type"] = res_types if len(res_types) > 1 else res_types[0]
            return res

        # Case 3: Both have non-null types
        k1 = non_null1[0]
        k2 = non_null2[0]

        # Widen integer + number to number
        if {k1, k2} == {"integer", "number"}:
            res_type = ["number", "null"] if has_null else "number"
            return {"type": res_type}

        # Same non-null type
        if k1 == k2:
            res_type = [k1, "null"] if has_null else k1

            if k1 == "object":
                props1 = s1.get("properties", {})
                props2 = s2.get("properties", {})
                all_keys = set(props1.keys()) | set(props2.keys())
                merged_props: Dict[str, Any] = {}
                for key in sorted(all_keys):
                    if key in props1 and key in props2:
                        merged_props[key] = self.merge(
                            props1[key],
                            props2[key],
                            current_depth=current_depth + 1,
                            seen=seen,
                        )
                    elif key in props1:
                        merged_props[key] = copy.deepcopy(props1[key])
                    else:
                        merged_props[key] = copy.deepcopy(props2[key])

                res: Dict[str, Any] = {"type": res_type, "properties": merged_props}

                # Intersect required fields
                req1 = set(s1.get("required", []))
                req2 = set(s2.get("required", []))
                common_req = [r for r in s1.get("required", []) if r in req2]
                if common_req:
                    res["required"] = sorted(common_req)
                return res

            if k1 == "array":
                res = {"type": res_type}
                items1 = s1.get("items")
                items2 = s2.get("items")
                if items1 and items2:
                    res["items"] = self.merge(
                        items1,
                        items2,
                        current_depth=current_depth + 1,
                        seen=seen,
                    )
                elif items1:
                    res["items"] = copy.deepcopy(items1)
                elif items2:
                    res["items"] = copy.deepcopy(items2)
                return res

            if k1 == "string":
                res = {"type": res_type}
                f1 = s1.get("format")
                f2 = s2.get("format")
                if f1 and f2 and f1 == f2:
                    res["format"] = f1
                return res

            return {"type": res_type}

        # Fallback to anyOf
        return {"anyOf": [copy.deepcopy(s1), copy.deepcopy(s2)]}


class ParameterInferrer:
    """
    Path parameter normalization and schema heuristics for path and query parameters.
    """

    # Express :param
    _EXPRESS_RE = re.compile(r":([a-zA-Z0-9_]+)")
    # Next.js [[...param]] (optional catch-all)
    _NEXT_OPT_CATCHALL_RE = re.compile(r"\[\[\.\.\.([a-zA-Z0-9_-]+)\]\]")
    # Next.js [...param] (catch-all)
    _NEXT_CATCHALL_RE = re.compile(r"\[\.\.\.([a-zA-Z0-9_-]+)\]")
    # Next.js [param]
    _NEXT_PARAM_RE = re.compile(r"\[([a-zA-Z0-9_-]+)\]")
    # Django <int:param>, <str:param>, <uuid:param>, <param>
    _DJANGO_RE = re.compile(r"<(?:[a-zA-Z_]\w*:)?([a-zA-Z0-9_-]+)>")
    # OpenAPI standard {param}
    _PARAM_EXTRACT_RE = re.compile(r"\{([a-zA-Z0-9_-]+)\}")

    @classmethod
    def normalize_path(cls, path: str) -> Tuple[str, List[str]]:
        """
        Normalizes Express :id, Next.js [id]/[...slug], Django <int:id> to OpenAPI standard {id}.
        Returns (normalized_path, list_of_extracted_path_param_names).
        """
        if not path:
            return "/", []

        norm = str(path).strip()
        if not norm.startswith("/"):
            norm = "/" + norm

        # Normalize Django converters e.g. <int:id> -> {id}
        norm = cls._DJANGO_RE.sub(r"{\1}", norm)
        # Normalize Next.js optional catch-all e.g. [[...slug]] -> {slug}
        norm = cls._NEXT_OPT_CATCHALL_RE.sub(r"{\1}", norm)
        # Normalize Next.js catch-all e.g. [...slug] -> {slug}
        norm = cls._NEXT_CATCHALL_RE.sub(r"{\1}", norm)
        # Normalize Next.js param e.g. [id] -> {id}
        norm = cls._NEXT_PARAM_RE.sub(r"{\1}", norm)
        # Normalize Express param e.g. :id -> {id}
        norm = cls._EXPRESS_RE.sub(r"{\1}", norm)

        # Extract all parameter names in order of appearance
        raw_params = cls._PARAM_EXTRACT_RE.findall(norm)
        # Deduplicate preserving order
        extracted_params = list(dict.fromkeys(raw_params))

        return norm, extracted_params

    @classmethod
    def infer_param_schema(
        cls,
        name: str,
        location: str = "query",
        sample_val: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Infers schema for path and query parameters using heuristics and sample data.
        Heuristics cover: id, uuid, slug, date, page, limit, is_*, order, etc.
        """
        inferrer = OpenAPISchemaInferrer()

        if sample_val is not None:
            if isinstance(sample_val, bool):
                return {"type": "boolean"}
            if isinstance(sample_val, int):
                return {"type": "integer"}
            if isinstance(sample_val, float):
                return {"type": "number"}
            if isinstance(sample_val, (bytes, bytearray)):
                return {"type": "string", "format": "binary"}
            if isinstance(sample_val, datetime.datetime):
                return {"type": "string", "format": "date-time"}
            if isinstance(sample_val, datetime.date):
                return {"type": "string", "format": "date"}
            if isinstance(sample_val, (list, tuple, set)):
                return {"type": "array"}
            if isinstance(sample_val, dict):
                return {"type": "object"}
            if isinstance(sample_val, str):
                s = sample_val.strip()
                s_lower = s.lower()
                if s_lower in ("true", "false"):
                    return {"type": "boolean"}
                if re.fullmatch(r"-?\d+", s):
                    return {"type": "integer"}
                if re.fullmatch(r"-?\d+\.\d+", s):
                    return {"type": "number"}
                fmt = inferrer.infer_string_format(s)
                if fmt:
                    return {"type": "string", "format": fmt}
                return {"type": "string"}

        name_str = str(name).encode("utf-8", errors="replace").decode("utf-8")
        clean = name_str.lower().replace("-", "_")

        # 1. UUID / GUID
        if clean in ("uuid", "guid") or clean.endswith(("_uuid", "_guid")) or clean.startswith(("uuid_", "guid_")):
            return {"type": "string", "format": "uuid"}

        # 2. Slug
        if clean == "slug" or clean.endswith("_slug") or clean.startswith("slug_"):
            return {"type": "string"}

        # 3. Date / DateTime
        if clean in (
            "timestamp", "created_at", "updated_at", "deleted_at",
            "published_at", "expires_at", "datetime", "date_time"
        ) or clean.endswith(("_at", "_datetime", "_timestamp")):
            return {"type": "string", "format": "date-time"}

        if clean in (
            "date", "start_date", "end_date", "from_date",
            "to_date", "birth_date", "due_date"
        ) or clean.endswith("_date") or clean.startswith("date_"):
            return {"type": "string", "format": "date"}

        # 4. Page pagination
        if clean in ("page", "page_number", "page_num", "page_index", "page_no", "p"):
            return {"type": "integer"}

        # 5. Limit / Offset / Size
        if clean in (
            "limit", "offset", "per_page", "size", "page_size",
            "count", "skip", "take", "max_results", "total",
            "step", "length", "batch_size"
        ):
            return {"type": "integer"}

        # 6. Boolean flag (is_*, has_*, active, etc.)
        if clean.startswith(("is_", "has_", "should_", "can_")) or clean in (
            "active", "enabled", "disabled", "verified", "archived",
            "deleted", "published", "draft", "debug", "verbose"
        ):
            return {"type": "boolean"}

        # 7. Order / Sort
        if clean in ("order", "order_by", "sort", "sort_by", "direction", "dir"):
            return {"type": "string"}

        # 8. ID / PK
        if clean in ("id", "pk") or clean.endswith(("_id", "_pk")):
            return {"type": "integer"}

        # 9. Email
        if clean in ("email", "mail") or clean.endswith(("_email", "_mail")):
            return {"type": "string", "format": "email"}

        # Default string fallback
        return {"type": "string"}
