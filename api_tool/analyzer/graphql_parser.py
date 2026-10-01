"""
GraphQL AST & Operation Harvester.

Analyzes JavaScript / TypeScript bundles and source files to extract:
1. Tagged template literals:
   - Apollo Client (`gql` from '@apollo/client')
   - urql (`gql` from 'urql')
   - Relay (`graphql` from 'react-relay')
   - graphql-request (`gql`, `request`)
2. Commented strings:
   - `/* GraphQL */` in backtick and quoted strings
   - `#graphql` comment annotations
3. Precompiled AST objects:
   - TypedDocumentNode from `@graphql-codegen/client-preset` (AST JSON with kind="OperationDefinition" / "Document")
   - Relay ConcreteRequest artifacts (kind="Request", params.text or fragment/operation trees)
4. GraphQL endpoints:
   - Apollo Client / urql client configurations (uri, url)
   - GraphQLClient & request constructors
   - fetch / axios / ky / $fetch calls targeting GraphQL paths
   - Standard path conventions (/graphql, /api/graphql, /v1/graphql, /query)

Uses `graphql-core` for AST validation, operation normalization, variable sample derivation,
with a resilient regex fallback for malformed or interpolated snippets.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from graphql import (
    DocumentNode,
    FragmentDefinitionNode,
    ListTypeNode,
    NamedTypeNode,
    NonNullTypeNode,
    OperationDefinitionNode,
    OperationType,
    parse,
    print_ast,
    value_from_ast_untyped,
)

from api_tool.models import GraphQLOperation


class GraphQLQueryExtractor:
    """
    Extracts GraphQL queries, mutations, subscriptions, and candidate endpoints
    from modern frontend JavaScript / TypeScript code and bundles.
    """

    def __init__(self, default_endpoint: str = "/graphql") -> None:
        self.default_endpoint = default_endpoint

    def extract_from_code(
        self, code: str, default_endpoint: str = "/graphql"
    ) -> List[GraphQLOperation]:
        """
        Extracts GraphQL operations from code.

        Supports:
        - Tagged template literals (`gql`...``, `graphql`...``)
        - Commented strings (`/* GraphQL */`...``, `#graphql`)
        - Precompiled AST object definitions (`kind: "OperationDefinition"`, `kind: "Document"`, Relay `ConcreteRequest`)

        Validates syntax using `graphql-core` and derives operation type, name,
        and variable samples. Falls back to resilient regex salvage on syntax errors.
        """
        if not code or not isinstance(code, str):
            return []

        # Determine target endpoint: check detected endpoints in code or use fallback
        detected_endpoints = self.detect_graphql_endpoints(code)
        if default_endpoint == "/graphql" and detected_endpoints:
            target_endpoint = detected_endpoints[0]
        else:
            target_endpoint = default_endpoint

        operations: List[GraphQLOperation] = []
        seen_keys: Set[Tuple[str, str, str]] = set()

        def add_operation(op: Optional[GraphQLOperation]) -> None:
            if not op:
                return
            key = (op.operation_type, op.operation_name, op.query_string.strip())
            if key not in seen_keys:
                seen_keys.add(key)
                operations.append(op)

        # 1. Extract and parse tagged template literals and commented strings
        template_snippets = self._extract_template_literals(code)
        for snippet in template_snippets:
            parsed_ops = self._parse_graphql_string(snippet, target_endpoint)
            for op in parsed_ops:
                add_operation(op)

        # 2. Extract and parse precompiled AST objects (TypedDocumentNode, Relay ConcreteRequest)
        ast_objects = self._extract_ast_objects(code)
        for obj in ast_objects:
            ops_from_ast = self._parse_ast_object(obj, target_endpoint)
            for op in ops_from_ast:
                add_operation(op)

        return operations

    def detect_graphql_endpoints(self, code: str) -> List[str]:
        """
        Identifies candidate GraphQL endpoints from Apollo client URLs,
        urql client configs, GraphQLClient calls, fetch/axios invocations,
        and standard path conventions.
        """
        if not code or not isinstance(code, str):
            return []

        endpoints: List[str] = []
        seen: Set[str] = set()

        def add_endpoint(ep: str) -> None:
            if not ep or not isinstance(ep, str):
                return
            ep = ep.strip().strip("'\"`")
            # Endpoint must start with / or http(s)://
            if not (ep.startswith("/") or ep.startswith("http://") or ep.startswith("https://")):
                return
            # Filter out non-endpoints / MIME types
            if ep.lower() in ("application/json", "application/graphql", "text/plain", "text/html"):
                return
            if ep not in seen:
                seen.add(ep)
                endpoints.append(ep)

        # 1. Apollo Client, urql, HttpLink: uri or url inside client initialization
        apollo_urql_pat = re.compile(
            r"""\b(?:uri|url|endpoint)["']?\s*:\s*["'`](https?://[^"'`\s\\]{1,2048}+|/[^"'`\s\\]{1,2048}+)["'`]""",
            re.IGNORECASE,
        )
        for m in apollo_urql_pat.finditer(code):
            url = m.group(1)
            url_lower = url.lower()
            if url.startswith("http") or any(k in url_lower for k in ("graphql", "gql", "query", "api/")):
                add_endpoint(url)

        # 2. new GraphQLClient(...) or request(...)
        graphql_client_pat = re.compile(
            r"""(?:new\s+GraphQLClient|\brequest)\s*\(\s*["'`](https?://[^"'`\s]+|/[^"'`\s]+)["'`]""",
            re.IGNORECASE,
        )
        for m in graphql_client_pat.finditer(code):
            add_endpoint(m.group(1))

        # 3. fetch / axios / $fetch / ky calls targeting graphql or query endpoints
        fetch_pat = re.compile(
            r"""\b(?:fetch|axios(?:\.(?:post|get|request))?|\$fetch|ky(?:\.(?:post|get))?)\s*\(\s*["'`](https?://[^"'`\s]+|/[^"'`\s]*)["'`]""",
            re.IGNORECASE,
        )
        for m in fetch_pat.finditer(code):
            url = m.group(1)
            if any(term in url.lower() for term in ("graphql", "gql", "/query")):
                add_endpoint(url)

        # 4. GraphQL environment variables and constants
        env_const_pat = re.compile(
            r"""\b([A-Za-z0-9_]+)\s*[:=]\s*["'`](https?://[^"'`\s\\]{1,2048}+|/[^"'`\s\\]{1,2048}+)["'`]"""
        )
        for m in env_const_pat.finditer(code):
            var_name = m.group(1).upper()
            if "GRAPHQL" in var_name or "GQL" in var_name:
                add_endpoint(m.group(2))

        # 5. Generic string literals that are standard GraphQL endpoint paths
        generic_pat = re.compile(
            r"""["'`](https?://[a-zA-Z0-9_\-\.:]+(?:/(?:api|v[0-9]+)?/graphql|/query)/?|/(?:(?:api|v[0-9]+)/)?graphql|/query)["'`]""",
            re.IGNORECASE,
        )
        for m in generic_pat.finditer(code):
            add_endpoint(m.group(1))

        return endpoints

    # -------------------------------------------------------------------------
    # Template Literal & String Extraction
    # -------------------------------------------------------------------------

    def _extract_template_literals(self, code: str) -> List[str]:
        """
        Extracts candidate GraphQL strings from tagged templates, function calls,
        and comment annotations.
        """
        snippets: List[str] = []
        seen: Set[str] = set()

        def add_snippet(s: str) -> None:
            clean = s.strip()
            if clean and clean not in seen:
                seen.add(clean)
                snippets.append(clean)

        # Pattern A: gql / graphql tags or calls with backticks: gql`...`, graphql`...`, /* GraphQL */ `...`
        pat_backtick = re.compile(
            r"""(?:\b(?:gql|graphql)\s*(?:\(\s*)?|/\*\s*GraphQL\s*\*/\s*)`((?:[^`\\]|\\.)*)`""",
            re.IGNORECASE | re.DOTALL,
        )
        for m in pat_backtick.finditer(code):
            add_snippet(self._unescape_string(m.group(1)))

        # Pattern B: gql(...) or /* GraphQL */ with quotes (single or double)
        pat_quotes = re.compile(
            r"""(?:\b(?:gql|graphql)\s*\(\s*|/\*\s*GraphQL\s*\*/\s*)(["'])((?:(?!\1)[^\\]|\\.)*)\1""",
            re.IGNORECASE | re.DOTALL,
        )
        for m in pat_quotes.finditer(code):
            add_snippet(self._unescape_string(m.group(2)))

        # Pattern C: #graphql comment inside backtick or quotes
        pat_hash_backtick = re.compile(
            r"""`\s*#graphql\s+((?:[^`\\]|\\.)*)`""",
            re.IGNORECASE | re.DOTALL,
        )
        for m in pat_hash_backtick.finditer(code):
            add_snippet(self._unescape_string(m.group(1)))

        pat_hash_quotes = re.compile(
            r"""(["'])\s*#graphql\s+((?:(?!\1)[^\\]|\\.)*)\1""",
            re.IGNORECASE | re.DOTALL,
        )
        for m in pat_hash_quotes.finditer(code):
            add_snippet(self._unescape_string(m.group(2)))

        # Pattern D: Untagged template literals starting with query/mutation/subscription
        pat_standalone = re.compile(
            r"""`\s*(?:#graphql\s*)?((?:query|mutation|subscription)\b(?:[^`\\]|\\.)*)`""",
            re.IGNORECASE | re.DOTALL,
        )
        for m in pat_standalone.finditer(code):
            add_snippet(self._unescape_string(m.group(1)))

        return snippets

    def _unescape_string(self, s: str) -> str:
        """Unescapes common JS escape sequences."""
        return (
            s.replace(r"\n", "\n")
            .replace(r"\t", "\t")
            .replace(r"\r", "\r")
            .replace(r'\"', '"')
            .replace(r"\'", "'")
            .replace(r"\`", "`")
            .replace(r"\\", "\\")
        )

    def _strip_interpolations(self, query_str: str) -> str:
        """
        Replaces JS template literal interpolations `${...}` with comments
        to allow clean parsing by graphql-core.
        """
        s = query_str
        prev = None
        while prev != s:
            prev = s
            s = re.sub(r"\$\{[^{}]*\}", "\n# [interpolated]\n", s)
        return s

    # -------------------------------------------------------------------------
    # GraphQL String Parsing (graphql-core + fallback)
    # -------------------------------------------------------------------------

    def _parse_graphql_string(self, raw_query: str, endpoint: str) -> List[GraphQLOperation]:
        """
        Parses a raw GraphQL query string using graphql-core AST parser.
        Falls back to resilient regex salvage if AST parsing fails.
        """
        cleaned = self._strip_interpolations(raw_query).strip()
        if not cleaned:
            return []

        # Remove leading #graphql comment tag if present
        cleaned_no_tag = re.sub(r"^\s*#graphql\s*", "", cleaned).strip()

        try:
            doc = parse(cleaned_no_tag)
            ops = [d for d in doc.definitions if isinstance(d, OperationDefinitionNode)]
            frags = [d for d in doc.definitions if isinstance(d, FragmentDefinitionNode)]

            if not ops:
                # If there are only fragments or no operations defined, fallback
                return []

            results: List[GraphQLOperation] = []
            for op_def in ops:
                op_type = op_def.operation.value if hasattr(op_def.operation, "value") else str(op_def.operation)
                op_name = op_def.name.value if op_def.name else "anonymous"

                # Generate clean query string with any fragments attached
                single_doc = DocumentNode(definitions=(op_def, *frags))
                query_str = print_ast(single_doc).strip()

                # Extract variable samples
                vars_sample = self._extract_variables_sample(op_def)

                results.append(
                    GraphQLOperation(
                        operation_type=op_type,
                        operation_name=op_name,
                        query_string=query_str,
                        endpoint=endpoint,
                        variables_sample=vars_sample,
                    )
                )
            return results
        except Exception:
            # Resilient fallback on parsing error
            salvaged = self._regex_fallback_extract(raw_query, endpoint)
            return [salvaged] if salvaged else []

    def _extract_variables_sample(
        self, op_def: OperationDefinitionNode
    ) -> Optional[Dict[str, Any]]:
        """Extracts variable names and infers sample values from AST VariableDefinitions."""
        if not op_def.variable_definitions:
            return None

        sample: Dict[str, Any] = {}
        for var in op_def.variable_definitions:
            vname = var.variable.name.value
            if var.default_value is not None:
                try:
                    sample[vname] = value_from_ast_untyped(var.default_value)
                    continue
                except Exception:
                    pass
            sample[vname] = self._sample_value_from_type_node(var.type)

        return sample if sample else None

    def _sample_value_from_type_node(self, type_node: Any) -> Any:
        """Infers realistic mock / sample value from AST TypeNode."""
        if isinstance(type_node, NonNullTypeNode):
            return self._sample_value_from_type_node(type_node.type)
        if isinstance(type_node, ListTypeNode):
            return [self._sample_value_from_type_node(type_node.type)]
        if isinstance(type_node, NamedTypeNode):
            tname = type_node.name.value
            if tname in ("Int", "Integer"):
                return 10
            elif tname == "Float":
                return 1.0
            elif tname in ("Boolean", "Bool"):
                return True
            elif tname == "ID":
                return "1"
            elif tname == "String":
                return "sample"
            else:
                # Custom input object or enum
                return {}
        return "sample"

    def _regex_fallback_extract(self, snippet: str, endpoint: str) -> Optional[GraphQLOperation]:
        """
        Resilient regex fallback parser that salvages operation type, name,
        and variables from broken or partially-interpolated GraphQL snippets.
        """
        clean = snippet.strip()
        if not clean:
            return None

        # Operation type: query, mutation, or subscription
        type_match = re.search(r"\b(query|mutation|subscription)\b", clean, re.IGNORECASE)
        op_type = type_match.group(1).lower() if type_match else "query"

        # Operation name
        name_match = re.search(
            r"\b(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)", clean, re.IGNORECASE
        )
        if name_match:
            op_name = name_match.group(1)
        else:
            # Fallback to first field selection
            field_match = re.search(r"\{\s*([a-zA-Z0-9_]+)", clean)
            op_name = field_match.group(1) if field_match else "anonymous"

        # Variables extraction
        vars_sample: Optional[Dict[str, Any]] = None
        vars_match = re.search(r"\(([^)]+)\)", clean)
        if vars_match:
            sample_dict: Dict[str, Any] = {}
            for chunk in vars_match.group(1).split(","):
                vmatch = re.search(
                    r"\$([a-zA-Z0-9_]+)(?:\s*:\s*([^=,)]+))?(?:\s*=\s*([^,)]+))?", chunk
                )
                if vmatch:
                    vname = vmatch.group(1)
                    vtype = (vmatch.group(2) or "String").strip().replace("!", "")
                    vdefault = vmatch.group(3)
                    if vdefault:
                        vdef_str = vdefault.strip().strip("\"'")
                        if vdef_str.isdigit():
                            sample_dict[vname] = int(vdef_str)
                        elif vdef_str.lower() in ("true", "false"):
                            sample_dict[vname] = vdef_str.lower() == "true"
                        else:
                            sample_dict[vname] = vdef_str
                    elif "Int" in vtype:
                        sample_dict[vname] = 10
                    elif "Float" in vtype:
                        sample_dict[vname] = 1.0
                    elif "Bool" in vtype:
                        sample_dict[vname] = True
                    elif "ID" in vtype:
                        sample_dict[vname] = "1"
                    else:
                        sample_dict[vname] = "sample"
            if sample_dict:
                vars_sample = sample_dict

        return GraphQLOperation(
            operation_type=op_type,
            operation_name=op_name,
            query_string=clean,
            endpoint=endpoint,
            variables_sample=vars_sample,
        )

    # -------------------------------------------------------------------------
    # Precompiled AST Extraction (TypedDocumentNode & Relay)
    # -------------------------------------------------------------------------

    def _extract_ast_objects(self, code: str) -> List[Dict[str, Any]]:
        """
        Locates and extracts precompiled AST object dictionaries from code,
        specifically TypedDocumentNode (OperationDefinition / Document) and Relay (Request).
        """
        ast_objects: List[Dict[str, Any]] = []
        seen_spans: Set[Tuple[int, int]] = set()

        # Match kind: "OperationDefinition" or kind: "Document" or kind: "Request"
        marker_pat = re.compile(
            r"""["']?kind["']?\s*:\s*["'](OperationDefinition|Document|Request)["']""",
            re.IGNORECASE,
        )

        for match in marker_pat.finditer(code):
            pos = match.start()
            # Scan backward to enclosing object
            obj_str, span = self._find_enclosing_object_with_span(code, pos)
            if not obj_str or span in seen_spans:
                continue

            parsed_dict = self._parse_js_object(obj_str)
            if parsed_dict and isinstance(parsed_dict, dict):
                ast_objects.append(parsed_dict)
                seen_spans.add(span)
            else:
                # If full object JS parsing fails, attempt regex salvage of AST fields
                salvaged_ast = self._salvage_ast_from_text(obj_str)
                if salvaged_ast:
                    ast_objects.append(salvaged_ast)
                    seen_spans.add(span)

        return ast_objects

    def _find_enclosing_object_with_span(
        self, code: str, pos: int
    ) -> Tuple[Optional[str], Tuple[int, int]]:
        """
        Finds the opening and matching closing braces for the object enclosing pos.
        Returns the object substring and its (start, end) span.
        """
        depth = 0
        start_idx: Optional[int] = None
        min_idx = max(0, pos - 50000)
        i = pos
        while i >= min_idx:
            c = code[i]
            if c == "}":
                depth += 1
            elif c == "{":
                if depth == 0:
                    start_idx = i
                    break
                depth -= 1
            i -= 1

        if start_idx is None:
            return None, (-1, -1)

        depth = 0
        in_str: Optional[str] = None
        escape = False
        max_idx = min(len(code), start_idx + 100000)
        for j in range(start_idx, max_idx):
            c = code[j]
            if in_str:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == in_str:
                    in_str = None
                continue
            if c in ('"', "'", "`"):
                in_str = c
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return code[start_idx : j + 1], (start_idx, j + 1)

        return None, (-1, -1)

    def _parse_js_object(self, js_str: str) -> Optional[Dict[str, Any]]:
        """
        Safely converts a JavaScript object literal into a Python dict.
        Handles unquoted keys, single quotes, comments, and trailing commas.
        """
        try:
            return json.loads(js_str)
        except Exception:
            pass

        s = js_str
        # 1. Strip comments
        s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
        s = re.sub(r"//[^\n]*", "", s)
        # 2. Normalize JS undefined to null
        s = re.sub(r"\bundefined\b", "null", s)
        # 3. Quote unquoted keys: { key: or , key: or [ key:
        s = re.sub(r"([{,]\s*)([a-zA-Z0-9_$]+)\s*:", r'\1"\2":', s)
        # 4. Convert single-quoted strings to double quotes
        s = re.sub(r"'([^'\\]*(?:\\.[^'\\]*)*)'", r'"\1"', s)
        # 5. Remove trailing commas
        s = re.sub(r",\s*([\]}])", r"\1", s)

        try:
            return json.loads(s)
        except Exception:
            return None

    def _salvage_ast_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """Resilient regex extraction for AST fields if JS object parsing fails."""
        kind_m = re.search(r'["\']?kind["\']?\s*:\s*["\'](OperationDefinition|Request|Document)["\']', text)
        if not kind_m:
            return None

        kind = kind_m.group(1)
        type_m = re.search(r'["\']?(?:operation|operationKind)["\']?\s*:\s*["\'](query|mutation|subscription)["\']', text, re.I)
        op_type = type_m.group(1).lower() if type_m else "query"

        name_m = re.search(
            r'["\']?name["\']?\s*:\s*(?:\{[^}]*?["\']?value["\']?\s*:\s*["\']([a-zA-Z0-9_]+)["\']|["\']([a-zA-Z0-9_]+)["\'])',
            text,
        )
        op_name = (name_m.group(1) or name_m.group(2)) if name_m else "anonymous"

        # Check for embedded text property (Relay)
        text_m = re.search(r'["\']?text["\']?\s*:\s*(["\'])((?:(?!\1)[^\\]|\\.)*)\1', text)
        raw_text = self._unescape_string(text_m.group(2)) if text_m else None

        if kind == "Request":
            return {
                "kind": "Request",
                "operationKind": op_type,
                "name": op_name,
                "params": {"name": op_name, "operationKind": op_type, "text": raw_text},
            }
        else:
            return {
                "kind": "OperationDefinition",
                "operation": op_type,
                "name": {"kind": "Name", "value": op_name},
                "_raw_text": raw_text,
            }

    def _parse_ast_object(
        self, node: Dict[str, Any], endpoint: str
    ) -> List[GraphQLOperation]:
        """
        Converts a precompiled AST dictionary (Document, OperationDefinition, or Relay Request)
        into GraphQLOperation instances.
        """
        kind = node.get("kind", "")
        if kind == "Request":
            return self._parse_relay_request_node(node, endpoint)
        elif kind in ("Document", "OperationDefinition"):
            query_str = self._ast_dict_to_graphql_string(node)
            if query_str:
                return self._parse_graphql_string(query_str, endpoint)
            # If reconstruction was empty, fallback
            op_name = self._extract_ast_name(node) or "anonymous"
            op_type = node.get("operation", "query")
            return [
                GraphQLOperation(
                    operation_type=op_type,
                    operation_name=op_name,
                    query_string=f"{op_type} {op_name} {{ __typename }}",
                    endpoint=endpoint,
                )
            ]
        return []

    def _parse_relay_request_node(
        self, node: Dict[str, Any], endpoint: str
    ) -> List[GraphQLOperation]:
        """Extracts operation from Relay ConcreteRequest node."""
        params = node.get("params", {})
        op_name = params.get("name") or node.get("name") or "RelayOperation"
        op_kind = params.get("operationKind") or node.get("operationKind") or "query"
        raw_text = params.get("text") or node.get("text")

        if raw_text and isinstance(raw_text, str) and raw_text.strip():
            # If text is populated (standard non-persisted query), parse directly
            return self._parse_graphql_string(raw_text, endpoint)

        # Persisted query without text - reconstruct from Relay fragment/operation definitions
        args_def = node.get("operation", {}).get("argumentDefinitions") or []
        var_strs: List[str] = []
        vars_sample: Dict[str, Any] = {}
        for arg in args_def:
            vname = arg.get("name")
            if not vname:
                continue
            vtype = arg.get("type", "ID")
            var_strs.append(f"${vname}: {vtype}")
            vars_sample[vname] = "1" if "ID" in vtype else "sample"

        vars_part = f"({', '.join(var_strs)})" if var_strs else ""

        sels = node.get("fragment", {}).get("selections") or node.get("operation", {}).get("selections")
        if sels:
            body = self._relay_selections_to_str(sels)
        else:
            body = "__typename"

        reconstructed_query = f"{op_kind} {op_name}{vars_part} {{\n  {body}\n}}"
        return self._parse_graphql_string(reconstructed_query, endpoint)

    def _relay_selections_to_str(self, selections: List[Dict[str, Any]], indent: str = "  ") -> str:
        """Recursively formats Relay AST selections into GraphQL query fields."""
        lines: List[str] = []
        for sel in selections:
            name = sel.get("name")
            if not name:
                continue
            alias = sel.get("alias")
            field = f"{alias}: {name}" if alias else name
            args = sel.get("args")
            if args:
                arg_strs: List[str] = []
                for a in args:
                    aname = a.get("name")
                    if "variableName" in a:
                        arg_strs.append(f"{aname}: ${a['variableName']}")
                    elif "value" in a:
                        arg_strs.append(f"{aname}: {json.dumps(a['value'])}")
                if arg_strs:
                    field += f"({', '.join(arg_strs)})"
            sub_sels = sel.get("selections")
            if sub_sels:
                sub_str = self._relay_selections_to_str(sub_sels, indent + "  ")
                lines.append(f"{field} {{\n{indent}  {sub_str}\n{indent}}}")
            else:
                lines.append(field)
        return f"\n{indent}".join(lines)

    def _extract_ast_name(self, node: Dict[str, Any]) -> str:
        """Extracts name string from AST Name node or string."""
        name = node.get("name")
        if isinstance(name, dict):
            return name.get("value", "")
        elif isinstance(name, str):
            return name
        return ""

    def _ast_dict_to_graphql_string(self, node: Any) -> str:
        """
        Recursively converts a TypedDocumentNode / GraphQL-Codegen AST dictionary
        into a valid GraphQL query string.
        """
        if not isinstance(node, dict):
            return str(node) if node is not None else ""

        kind = node.get("kind", "")
        if kind == "Document":
            return "\n\n".join(
                filter(
                    None,
                    (self._ast_dict_to_graphql_string(d) for d in node.get("definitions", [])),
                )
            )
        elif kind == "OperationDefinition":
            op = node.get("operation", "query")
            name = self._extract_ast_name(node)
            var_defs = node.get("variableDefinitions", [])
            var_str = ""
            if var_defs:
                vars_list: List[str] = []
                for v in var_defs:
                    vname = self._extract_ast_name(v.get("variable", {}))
                    vtype = self._ast_dict_to_graphql_string(v.get("type"))
                    default = ""
                    if "defaultValue" in v and v["defaultValue"] is not None:
                        default = f" = {self._ast_dict_to_graphql_string(v['defaultValue'])}"
                    vars_list.append(f"${vname}: {vtype}{default}")
                var_str = f"({', '.join(vars_list)})"
            sel = self._ast_dict_to_graphql_string(node.get("selectionSet", {}))
            header = f"{op} {name}".strip() if name else op
            if var_str:
                header += f" {var_str}"
            return f"{header} {sel}".strip()
        elif kind == "FragmentDefinition":
            name = self._extract_ast_name(node)
            type_cond = self._extract_ast_name(node.get("typeCondition", {})) or self._ast_dict_to_graphql_string(
                node.get("typeCondition")
            )
            sel = self._ast_dict_to_graphql_string(node.get("selectionSet", {}))
            return f"fragment {name} on {type_cond} {sel}".strip()
        elif kind == "SelectionSet":
            selections = [
                self._ast_dict_to_graphql_string(s) for s in node.get("selections", [])
            ]
            return "{\n  " + "\n  ".join(filter(None, selections)) + "\n}"
        elif kind == "Field":
            alias = self._extract_ast_name(node.get("alias", {})) if isinstance(node.get("alias"), dict) else node.get("alias")
            name = self._extract_ast_name(node)
            field_str = f"{alias}: {name}" if alias else name
            args = node.get("arguments", [])
            if args:
                args_list = [
                    f"{self._extract_ast_name(a)}: {self._ast_dict_to_graphql_string(a.get('value'))}"
                    for a in args
                ]
                field_str += f"({', '.join(args_list)})"
            directives = node.get("directives", [])
            if directives:
                for d in directives:
                    field_str += f" @{self._extract_ast_name(d)}"
            if node.get("selectionSet"):
                field_str += f" {self._ast_dict_to_graphql_string(node['selectionSet'])}"
            return field_str
        elif kind == "FragmentSpread":
            return f"...{self._extract_ast_name(node)}"
        elif kind == "InlineFragment":
            type_cond = self._extract_ast_name(node.get("typeCondition", {}))
            cond = f" on {type_cond}" if type_cond else ""
            return f"...{cond} {self._ast_dict_to_graphql_string(node.get('selectionSet', {}))}"
        elif kind == "NamedType":
            return self._extract_ast_name(node)
        elif kind == "NonNullType":
            return f"{self._ast_dict_to_graphql_string(node.get('type'))}!"
        elif kind == "ListType":
            return f"[{self._ast_dict_to_graphql_string(node.get('type'))}]"
        elif kind == "Variable":
            return f"${self._extract_ast_name(node)}"
        elif kind in ("IntValue", "FloatValue", "EnumValue"):
            return str(node.get("value", ""))
        elif kind == "BooleanValue":
            return "true" if node.get("value") else "false"
        elif kind == "StringValue":
            val = str(node.get("value", "")).replace('"', '\\"')
            return f'"{val}"'
        elif kind == "NullValue":
            return "null"
        elif kind == "ListValue":
            items = [self._ast_dict_to_graphql_string(v) for v in node.get("values", [])]
            return f"[{', '.join(items)}]"
        elif kind == "ObjectValue":
            fields = [
                f"{self._extract_ast_name(f)}: {self._ast_dict_to_graphql_string(f.get('value'))}"
                for f in node.get("fields", [])
            ]
            return f"{{{', '.join(fields)}}}"
        elif "value" in node:
            return str(node["value"])
        return ""
