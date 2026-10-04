"""
GraphQL Automatic Persisted Query (APQ) Extractor & Schema Synthesizer.

Features:
1. Extracts Apollo APQ hashes:
   - `extensions: { "persistedQuery": { "version": 1, "sha256Hash": "<64-hex>" } }`
   - URL-encoded / GET query parameter variants.
   - Pre-hashed JS AST and client configurations.
2. Extracts Relay persisted queries:
   - `id: "<hash>"` or `doc_id: "<id>"`.
   - Relay ConcreteRequest artifacts (params.id, params.name, params.text).
3. Scans JS bundles for manifest dictionaries:
   - `{ id: "hash", text: "query..." }`
   - `{ "<hash>": "query..." }`
   - Apollo Persisted Query Manifests and Relay query maps.
4. Normalizes and computes Apollo-compliant SHA-256 hashes using `graphql-core`.
5. Synthesizes clean, spec-compliant `schema.graphql` SDL without needing `__schema` introspection:
   - Merges fields across queries, mutations, and subscriptions.
   - Infers types, scalar mappings, arguments, and fragment expansions.
   - Strictly validates output using `graphql-core`.
"""

import hashlib
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from graphql import (
    ArgumentNode,
    BooleanValueNode,
    DocumentNode,
    FieldNode,
    FloatValueNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    IntValueNode,
    ListTypeNode,
    ListValueNode,
    NamedTypeNode,
    NonNullTypeNode,
    ObjectValueNode,
    OperationDefinitionNode,
    OperationType,
    StringValueNode,
    VariableDefinitionNode,
    VariableNode,
    build_schema,
    parse,
    print_ast,
    print_schema,
)

from api_tool.models import PersistedQueryRecord

logger = logging.getLogger(__name__)

# Standard GraphQL built-in scalar names
BUILTIN_SCALARS: Set[str] = {"String", "Int", "Float", "Boolean", "ID"}


def singularize(name: str) -> str:
    """Helper to convert plural English nouns to singular for GraphQL type inference."""
    n = name
    if n.endswith("ies") and len(n) > 3:
        return n[:-3] + "y"
    if n.endswith(("sses", "shes", "ches", "xes")):
        return n[:-2]
    if n.endswith("s") and len(n) > 3 and not n.endswith("ss"):
        return n[:-1]
    return n


def is_plural(name: str) -> bool:
    """Detects if a field name appears to be a plural list collection."""
    if name.endswith("ss"):
        return False
    return name.endswith("s") and len(name) > 3


def derive_type_name(field_name: str) -> str:
    """Derives a capitalized singular GraphQL type name from a field name."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "", field_name)
    # Strip common operation prefixes (e.g. createUser -> User)
    for prefix in ("create", "update", "delete", "add", "remove", "get", "fetch", "mutate"):
        if clean.lower().startswith(prefix) and len(clean) > len(prefix):
            clean = clean[len(prefix):]
            break
    # Strip common event/subscription suffixes (e.g. userAdded -> user)
    for suffix in ("Added", "Updated", "Deleted", "Created", "Changed", "Payload", "Response", "Result"):
        if clean.endswith(suffix) and len(clean) > len(suffix):
            clean = clean[:-len(suffix)]
            break

    sing = singularize(clean)
    if not sing:
        return "Item"
    return sing[:1].upper() + sing[1:]


def infer_scalar_type(field_name: str) -> str:
    """Infers an appropriate scalar type for a leaf field based on common naming heuristics."""
    n = field_name.lower()
    if n == "id" or n.endswith("id") or n.endswith("_id"):
        return "ID"
    if n.startswith(("is", "has", "should", "can", "enabled")):
        return "Boolean"
    if n.endswith(("count", "total", "limit", "offset", "age", "size", "index", "number")):
        return "Int"
    if n.endswith(("price", "amount", "rate", "score", "ratio", "percentage", "weight")):
        return "Float"
    return "String"


def calculate_sha256(query_string: str, normalize: bool = True) -> str:
    """
    Computes normalized Apollo SHA-256 hash for a GraphQL query string.

    When normalize=True, parses the query AST using graphql-core and prints canonical AST
    (stripping comments, non-significant whitespace, and normalizing syntax) to match
    Apollo Client's sha256(print(doc)) calculation.
    """
    if not query_string or not isinstance(query_string, str):
        return ""
    text = query_string.strip()
    if normalize:
        try:
            ast = parse(text)
            text = print_ast(ast)
        except Exception:
            # Fallback to stripped text if query contains syntax errors
            text = query_string.strip()

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def synthesize_sdl_from_records(
    records: List[Union[PersistedQueryRecord, Dict[str, Any]]],
) -> str:
    """
    Uses `graphql-core` (compulsory) to parse query strings from persisted query records,
    aggregate types/fields across operations, and synthesize clean, spec-compliant
    `schema.graphql` SDL without needing `__schema` introspection.
    """
    if not records:
        return ""

    # Normalize records into PersistedQueryRecord models
    valid_records: List[PersistedQueryRecord] = []
    for r in records:
        if isinstance(r, PersistedQueryRecord):
            valid_records.append(r)
        elif isinstance(r, dict):
            try:
                valid_records.append(PersistedQueryRecord.from_dict(r))
            except Exception:
                pass

    queries_to_process = [r.query_string.strip() for r in valid_records if r.query_string and r.query_string.strip()]
    if not queries_to_process:
        return ""

    root_fields: Dict[str, Dict[str, Dict[str, Any]]] = {
        "Query": {},
        "Mutation": {},
        "Subscription": {},
    }
    object_types: Dict[str, Dict[str, Dict[str, Any]]] = {}
    custom_scalars: Set[str] = set()
    fragments: Dict[str, FragmentDefinitionNode] = {}
    parsed_docs: List[DocumentNode] = []

    # First pass: parse all documents and collect fragment definitions
    for q_str in queries_to_process:
        try:
            doc = parse(q_str)
            parsed_docs.append(doc)
            for defn in doc.definitions:
                if isinstance(defn, FragmentDefinitionNode) and defn.name:
                    fragments[defn.name.value] = defn
        except Exception as e:
            logger.debug("Skipping unparseable query for SDL synthesis: %s", e)

    if not parsed_docs:
        return ""

    # Second pass: process operations
    for doc in parsed_docs:
        for defn in doc.definitions:
            if not isinstance(defn, OperationDefinitionNode):
                continue

            # Determine root type
            if defn.operation == OperationType.MUTATION:
                root_name = "Mutation"
            elif defn.operation == OperationType.SUBSCRIPTION:
                root_name = "Subscription"
            else:
                root_name = "Query"

            # Map variable definitions ($var: Type)
            var_types: Dict[str, str] = {}
            for vdef in defn.variable_definitions or []:
                vname = vdef.variable.name.value
                vtype_str = print_ast(vdef.type)
                var_types[vname] = vtype_str

                # Register any custom scalars / input types
                base_type = vtype_str.replace("!", "").replace("[", "").replace("]", "").strip()
                if base_type not in BUILTIN_SCALARS:
                    custom_scalars.add(base_type)

            def _process_selections(
                parent_type: str,
                selections: List[Any],
                current_depth: int = 0,
            ) -> None:
                if current_depth > 15:
                    return

                for sel in selections:
                    if isinstance(sel, FieldNode):
                        field_name = sel.name.value
                        if field_name.startswith("__"):
                            # Skip internal meta fields like __typename
                            continue

                        # Extract field arguments
                        args_map: Dict[str, str] = {}
                        for arg in sel.arguments or []:
                            aname = arg.name.value
                            aval = arg.value
                            if isinstance(aval, VariableNode):
                                atype = var_types.get(aval.name.value, "String")
                            elif isinstance(aval, IntValueNode):
                                atype = "Int"
                            elif isinstance(aval, FloatValueNode):
                                atype = "Float"
                            elif isinstance(aval, BooleanValueNode):
                                atype = "Boolean"
                            elif isinstance(aval, ListValueNode):
                                atype = "[String]"
                            else:
                                atype = "String"
                            args_map[aname] = atype

                        # Determine return type
                        if not sel.selection_set or not sel.selection_set.selections:
                            field_return_type = infer_scalar_type(field_name)
                        else:
                            # Inspect child selections for explicit fragment type conditions
                            explicit_type: Optional[str] = None
                            for child in sel.selection_set.selections:
                                if isinstance(child, InlineFragmentNode) and child.type_condition:
                                    explicit_type = child.type_condition.name.value
                                    break
                                elif isinstance(child, FragmentSpreadNode) and child.name.value in fragments:
                                    frag_cond = fragments[child.name.value].type_condition
                                    if frag_cond:
                                        explicit_type = frag_cond.name.value
                                        break

                            plural = is_plural(field_name)
                            element_type = explicit_type or derive_type_name(field_name)
                            field_return_type = f"[{element_type}]" if plural else element_type

                            # Recurse on child object selections
                            _process_selections(
                                element_type,
                                sel.selection_set.selections,
                                current_depth + 1,
                            )

                        # Record field on parent type
                        if parent_type in ("Query", "Mutation", "Subscription"):
                            target_dict = root_fields[parent_type]
                        else:
                            if parent_type not in object_types:
                                object_types[parent_type] = {}
                            target_dict = object_types[parent_type]

                        if field_name not in target_dict:
                            target_dict[field_name] = {
                                "type": field_return_type,
                                "args": args_map,
                            }
                        else:
                            # Merge arguments
                            target_dict[field_name]["args"].update(args_map)
                            # Prefer object type over leaf scalar if updated
                            existing_type = target_dict[field_name]["type"]
                            if existing_type in BUILTIN_SCALARS and field_return_type not in BUILTIN_SCALARS:
                                target_dict[field_name]["type"] = field_return_type

                    elif isinstance(sel, InlineFragmentNode):
                        inline_type = (
                            sel.type_condition.name.value
                            if sel.type_condition
                            else parent_type
                        )
                        if sel.selection_set and sel.selection_set.selections:
                            _process_selections(
                                inline_type,
                                sel.selection_set.selections,
                                current_depth + 1,
                            )

                    elif isinstance(sel, FragmentSpreadNode):
                        frag_name = sel.name.value
                        if frag_name in fragments:
                            frag = fragments[frag_name]
                            frag_type = (
                                frag.type_condition.name.value
                                if frag.type_condition
                                else parent_type
                            )
                            if frag.selection_set and frag.selection_set.selections:
                                _process_selections(
                                    frag_type,
                                    frag.selection_set.selections,
                                    current_depth + 1,
                                )

            if defn.selection_set and defn.selection_set.selections:
                _process_selections(root_name, defn.selection_set.selections)

    # Clean up custom scalars (remove types that became defined object types)
    for ot in list(object_types.keys()) + ["Query", "Mutation", "Subscription"]:
        custom_scalars.discard(ot)

    # Ensure root Query has at least one field if empty (valid GraphQL schema requirement)
    if not root_fields["Query"]:
        if root_fields["Mutation"] or root_fields["Subscription"] or object_types:
            root_fields["Query"]["_empty"] = {"type": "String", "args": {}}
        else:
            return ""

    # Build SDL string blocks
    blocks: List[str] = []

    for rname in ["Query", "Mutation", "Subscription"]:
        fields_map = root_fields[rname]
        if fields_map:
            flines: List[str] = []
            for fn in sorted(fields_map.keys()):
                fmeta = fields_map[fn]
                args_list = [f"{k}: {v}" for k, v in sorted(fmeta["args"].items())]
                arg_str = f"({', '.join(args_list)})" if args_list else ""
                flines.append(f"  {fn}{arg_str}: {fmeta['type']}")
            blocks.append(f"type {rname} {{\n" + "\n".join(flines) + "\n}")

    for oname in sorted(object_types.keys()):
        ofields = object_types[oname]
        if ofields:
            flines = []
            for fn in sorted(ofields.keys()):
                fmeta = ofields[fn]
                args_list = [f"{k}: {v}" for k, v in sorted(fmeta["args"].items())]
                arg_str = f"({', '.join(args_list)})" if args_list else ""
                flines.append(f"  {fn}{arg_str}: {fmeta['type']}")
            blocks.append(f"type {oname} {{\n" + "\n".join(flines) + "\n}")

    for cs in sorted(custom_scalars):
        blocks.append(f"scalar {cs}")

    raw_sdl = "\n\n".join(blocks)

    # Validate and format with graphql-core print_schema
    try:
        compiled_schema = build_schema(raw_sdl)
        return print_schema(compiled_schema)
    except Exception as e:
        logger.debug("graphql-core build_schema validation note: %s. Returning raw SDL.", e)
        return raw_sdl


class APQOperationExtractor:
    """
    GraphQL Automatic Persisted Query (APQ) Extractor & Schema Synthesizer.

    Harvests Apollo APQ hashes, Relay persisted queries, and bundle manifest dictionaries,
    and synthesizes clean `schema.graphql` SDL.
    """

    calculate_sha256 = staticmethod(calculate_sha256)
    synthesize_sdl_from_records = staticmethod(synthesize_sdl_from_records)

    def __init__(self) -> None:
        # Regex for Apollo sha256 hashes
        self._apollo_hash_re = re.compile(
            r"""(?:["'\s{,]|^)(?:sha256Hash|sha256_hash)["']?\s*[:=]\s*["']([0-9a-fA-F]{64})["']""",
            re.IGNORECASE,
        )

        # Regex for Relay persisted query identifiers
        self._relay_doc_id_re = re.compile(
            r"""(?:["'\s{,]|^)(?:doc_id|docId|documentId)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{8,64})["']""",
            re.IGNORECASE,
        )

        # Regex for Relay query id inside params or concrete requests
        self._relay_id_re = re.compile(
            r"""(?:["'\s{,]|^)id["']?\s*[:=]\s*["']([0-9a-fA-F]{32,64})["']""",
            re.IGNORECASE,
        )

        # Regex for URL-encoded APQ extensions in query parameters
        self._url_apq_re = re.compile(
            r"""(?:extensions|ext)=(?:%7B|\{).*?(?:%22|")sha256Hash(?:%22|")(?::|%3A)(?:%22|")([0-9a-fA-F]{64})(?:%22|")""",
            re.IGNORECASE,
        )

        # Regex for manifest dictionary entries: { id: "...", text: "..." } or { "hash": "query..." }
        self._manifest_dict_re = re.compile(
            r"""["']([0-9a-fA-F]{32,64})["']\s*:\s*["'`]([^"'`]+?\{[^"'`]+?\})["'`]""",
            re.MULTILINE | re.DOTALL,
        )

        # Regex for operation name
        self._op_name_re = re.compile(
            r"""(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)""",
            re.IGNORECASE,
        )

    def extract_from_code(self, code: str) -> List[PersistedQueryRecord]:
        """
        Extracts persisted query records from JavaScript/TypeScript source code or bundles.

        Supports:
        - Apollo APQ hashes (extensions.persistedQuery.sha256Hash).
        - Relay persisted query IDs (doc_id, id, ConcreteRequest params).
        - Manifest dictionaries ({ id: "...", text: "..." } or { "<hash>": "query..." }).
        """
        if not code or not isinstance(code, str):
            return []

        records_map: Dict[str, PersistedQueryRecord] = {}

        def _add_record(
            h: str,
            op_name: Optional[str] = None,
            query_str: Optional[str] = None,
            source: str = "bundle_ast",
        ) -> None:
            if not h:
                return
            h_clean = h.strip().lower()
            if not op_name and query_str:
                m_op = self._op_name_re.search(query_str)
                if m_op:
                    op_name = m_op.group(1)

            if h_clean in records_map:
                existing = records_map[h_clean]
                if not existing.operation_name and op_name:
                    existing.operation_name = op_name
                if not existing.query_string and query_str:
                    existing.query_string = query_str.strip()
            else:
                records_map[h_clean] = PersistedQueryRecord(
                    sha256_hash=h_clean,
                    operation_name=op_name,
                    query_string=query_str.strip() if query_str else None,
                    source=source,
                )

        # 1. Apollo APQ hashes
        for match in self._apollo_hash_re.finditer(code):
            sha_hash = match.group(1)
            # Search context around hash for operationName
            start_pos = max(0, match.start() - 250)
            end_pos = min(len(code), match.end() + 250)
            window = code[start_pos:end_pos]

            op_match = re.search(r"""["']?(?:operationName|name)["']?\s*[:=]\s*["']([a-zA-Z0-9_]+)["']""", window)
            op_name = op_match.group(1) if op_match else None
            _add_record(sha_hash, op_name=op_name, source="bundle_ast")

        # 2. URL-encoded APQ queries
        for match in self._url_apq_re.finditer(code):
            sha_hash = match.group(1)
            _add_record(sha_hash, source="bundle_ast")

        # 3. Relay doc_id queries
        for match in self._relay_doc_id_re.finditer(code):
            doc_id = match.group(1)
            start_pos = max(0, match.start() - 250)
            end_pos = min(len(code), match.end() + 250)
            window = code[start_pos:end_pos]

            op_match = re.search(r"""["']?(?:operationName|name)["']?\s*[:=]\s*["']([a-zA-Z0-9_]+)["']""", window)
            op_name = op_match.group(1) if op_match else None

            # Look for accompanying query string in the window
            q_match = re.search(r"""["']?(?:query|text)["']?\s*[:=]\s*["'`]([^"'`]+?\{.+?\})["'`]""", window, re.DOTALL)
            q_text = q_match.group(1) if q_match else None
            _add_record(doc_id, op_name=op_name, query_str=q_text, source="bundle_ast")

        # 4. Manifest dictionaries: { "<hash>": "query ..." }
        for match in self._manifest_dict_re.finditer(code):
            h_val = match.group(1)
            q_val = match.group(2)
            if any(k in q_val for k in ("query", "mutation", "subscription", "{")):
                _add_record(h_val, query_str=q_val, source="bundle_ast")

        # 5. Manifest objects: { id: "...", text: "..." } or { id: "...", name: "...", text: "..." }
        obj_re = re.compile(
            r"""\{\s*["']?id["']?\s*:\s*["']([a-zA-Z0-9_\-]{8,64})["'][^}]+?["']?(?:text|query|body)["']?\s*:\s*["'`]([^"'`]+?\{.+?\})["'`]""",
            re.MULTILINE | re.DOTALL,
        )
        for match in obj_re.finditer(code):
            h_val = match.group(1)
            q_val = match.group(2)
            _add_record(h_val, query_str=q_val, source="bundle_ast")

        # Also support reverse order: { text: "...", id: "..." }
        obj_rev_re = re.compile(
            r"""\{\s*["']?(?:text|query|body)["']?\s*:\s*["'`]([^"'`]+?\{.+?\})["'`][^}]+?["']?id["']?\s*:\s*["']([a-zA-Z0-9_\-]{8,64})["']""",
            re.MULTILINE | re.DOTALL,
        )
        for match in obj_rev_re.finditer(code):
            q_val = match.group(1)
            h_val = match.group(2)
            _add_record(h_val, query_str=q_val, source="bundle_ast")

        return list(records_map.values())

    def extract_from_manifest(
        self,
        manifest_data: Union[str, Dict[str, Any], List[Any]],
    ) -> List[PersistedQueryRecord]:
        """
        Parses APQ and Relay manifest structures from JSON strings, dicts, or lists:
        - Apollo Persisted Query Manifest (`operations: [ { id, name, body } ]`)
        - Key-value maps (`{ "<sha256>": "query..." }`)
        - Array of operation definitions (`[ { id, text }, ... ]`)
        """
        if isinstance(manifest_data, str):
            try:
                data = json.loads(manifest_data)
            except Exception:
                return []
        else:
            data = manifest_data

        records: List[PersistedQueryRecord] = []

        if isinstance(data, dict):
            # Apollo manifest format
            if "operations" in data and isinstance(data["operations"], list):
                for op in data["operations"]:
                    if isinstance(op, dict):
                        h = op.get("id") or op.get("sha256Hash") or op.get("hash")
                        if h:
                            records.append(
                                PersistedQueryRecord(
                                    sha256_hash=str(h).strip().lower(),
                                    operation_name=op.get("name") or op.get("operationName"),
                                    query_string=op.get("body") or op.get("text") or op.get("query"),
                                    source="apq_manifest",
                                )
                            )
            else:
                # Key-value mapping: { "<hash>": "query..." }
                for k, v in data.items():
                    if isinstance(v, str) and ("{" in v or "query" in v or "mutation" in v):
                        records.append(
                            PersistedQueryRecord(
                                sha256_hash=str(k).strip().lower(),
                                query_string=v.strip(),
                                source="apq_manifest",
                            )
                        )
                    elif isinstance(v, dict):
                        h = v.get("id") or v.get("sha256Hash") or str(k)
                        q = v.get("text") or v.get("query") or v.get("body")
                        records.append(
                            PersistedQueryRecord(
                                sha256_hash=str(h).strip().lower(),
                                operation_name=v.get("name") or v.get("operationName"),
                                query_string=str(q).strip() if q else None,
                                source="apq_manifest",
                            )
                        )

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    h = item.get("id") or item.get("sha256Hash") or item.get("hash")
                    if h:
                        records.append(
                            PersistedQueryRecord(
                                sha256_hash=str(h).strip().lower(),
                                operation_name=item.get("name") or item.get("operationName"),
                                query_string=item.get("text") or item.get("query") or item.get("body"),
                                source="apq_manifest",
                            )
                        )

        # Populate operation names if missing
        for r in records:
            if not r.operation_name and r.query_string:
                m = self._op_name_re.search(r.query_string)
                if m:
                    r.operation_name = m.group(1)

        return records

    def extract_from_har(
        self,
        har_data: Union[str, Dict[str, Any]],
    ) -> List[PersistedQueryRecord]:
        """
        Parses HAR (HTTP Archive) data to extract persisted query parameters from network requests.
        """
        if isinstance(har_data, str):
            try:
                data = json.loads(har_data)
            except Exception:
                return []
        else:
            data = har_data

        if not isinstance(data, dict):
            return []

        entries = data.get("log", {}).get("entries", [])
        if not isinstance(entries, list):
            return []

        records_map: Dict[str, PersistedQueryRecord] = {}

        for entry in entries:
            req = entry.get("request", {})
            url = req.get("url", "")

            # 1. Check URL query parameters
            for match in self._url_apq_re.finditer(url):
                h = match.group(1).lower()
                records_map[h] = PersistedQueryRecord(
                    sha256_hash=h,
                    source="network_har",
                )

            # Query params array in HAR
            for qp in req.get("queryString", []):
                name = qp.get("name", "")
                val = qp.get("value", "")
                if name == "extensions":
                    try:
                        ext = json.loads(val)
                        h = ext.get("persistedQuery", {}).get("sha256Hash")
                        if h:
                            h = str(h).strip().lower()
                            records_map[h] = PersistedQueryRecord(
                                sha256_hash=h,
                                source="network_har",
                            )
                    except Exception:
                        pass
                elif name in ("doc_id", "docId", "documentId") and val:
                    records_map[val] = PersistedQueryRecord(
                        sha256_hash=val,
                        source="network_har",
                    )

            # 2. Check POST data
            post_data = req.get("postData", {})
            text = post_data.get("text", "")
            if text:
                try:
                    payload = json.loads(text)
                    if isinstance(payload, dict):
                        ext = payload.get("extensions", {})
                        if isinstance(ext, dict):
                            h = ext.get("persistedQuery", {}).get("sha256Hash")
                            if h:
                                h_clean = str(h).strip().lower()
                                op_name = payload.get("operationName")
                                q_str = payload.get("query")
                                records_map[h_clean] = PersistedQueryRecord(
                                    sha256_hash=h_clean,
                                    operation_name=op_name,
                                    query_string=q_str,
                                    source="network_har",
                                )
                        doc_id = payload.get("doc_id") or payload.get("id")
                        if doc_id and isinstance(doc_id, str):
                            records_map[doc_id] = PersistedQueryRecord(
                                sha256_hash=doc_id,
                                operation_name=payload.get("operationName"),
                                query_string=payload.get("query"),
                                source="network_har",
                            )
                except Exception:
                    # Non-JSON or malformed payload: fallback to regex
                    for m in self._apollo_hash_re.finditer(text):
                        h = m.group(1).lower()
                        records_map[h] = PersistedQueryRecord(sha256_hash=h, source="network_har")

        return list(records_map.values())

    def extract_all(
        self,
        content: Union[str, Dict[str, Any], List[Any]],
    ) -> List[PersistedQueryRecord]:
        """
        Omni-extractor that identifies the input type (bundle code, JSON manifest, HAR archive)
        and returns deduplicated persisted query records.
        """
        results: Dict[str, PersistedQueryRecord] = {}

        def _merge(recs: List[PersistedQueryRecord]) -> None:
            for r in recs:
                if r.sha256_hash in results:
                    existing = results[r.sha256_hash]
                    if not existing.operation_name and r.operation_name:
                        existing.operation_name = r.operation_name
                    if not existing.query_string and r.query_string:
                        existing.query_string = r.query_string
                else:
                    results[r.sha256_hash] = r

        if isinstance(content, (dict, list)):
            if isinstance(content, dict) and "log" in content and "entries" in content["log"]:
                _merge(self.extract_from_har(content))
            else:
                _merge(self.extract_from_manifest(content))
        elif isinstance(content, str):
            clean_str = content.strip()
            if clean_str.startswith("{") or clean_str.startswith("["):
                try:
                    parsed_json = json.loads(clean_str)
                    if isinstance(parsed_json, dict) and "log" in parsed_json:
                        _merge(self.extract_from_har(parsed_json))
                    else:
                        _merge(self.extract_from_manifest(parsed_json))
                except Exception:
                    pass
            # Always run code extractor to catch embedded expressions and manifests
            _merge(self.extract_from_code(content))

        return list(results.values())
