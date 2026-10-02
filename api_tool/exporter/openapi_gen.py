"""
OpenAPI 3.1.0 Specification Generator and Pure-Python YAML Serializer.
Zero external dependencies, Termux and Linux compatible, strict JSON Schema 2020-12 alignment.
"""

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from api_tool.exporter.schema_inference import OpenAPISchemaInferrer, ParameterInferrer
from api_tool.models import DiscoveredEndpoint, DiscoveredParameter, DiscoveredResponse, ScanResult


class PureYamlDumper:
    """
    Zero-dependency, pure-Python YAML serializer.
    Correctly handles YAML quoting for OpenAPI status codes ("200":),
    path templates with braces ("/{id}":), and string scalars ("true", "false", "null").
    """

    def __init__(self, indent: int = 2, max_depth: int = 150):
        self.indent_spaces = indent
        self.max_depth = max_depth

    @classmethod
    def dump(cls, data: Any, indent: int = 2, max_depth: int = 150) -> str:
        """Classmethod shorthand for dumping data to YAML string."""
        dumper = cls(indent=indent, max_depth=max_depth)
        return dumper.serialize(data)

    def serialize(self, data: Any) -> str:
        """Serializes Python dictionary/list/scalars into YAML 1.2 compliant string."""
        lines: List[str] = []
        seen: Set[int] = set()
        if isinstance(data, dict):
            self._dump_dict(data, 0, lines, seen)
        elif isinstance(data, (list, tuple)):
            self._dump_list(data, 0, lines, seen)
        else:
            lines.append(self._format_scalar(data, 0))
        return "\n".join(lines) + "\n"

    def _format_key(self, key: Any) -> str:
        key_str = str(key)
        # Always quote numeric keys (OpenAPI status codes like "200")
        if key_str.isdigit():
            return f'"{key_str}"'
        # Always quote booleans and null words as keys
        if key_str.lower() in ("true", "false", "null", "yes", "no", "on", "off", "~"):
            return f'"{key_str}"'
        # Quote path templates containing braces, slashes, colons, or special YAML symbols
        if any(c in key_str for c in '{}[],&*#?|->!%@\\"\':/') or key_str.startswith(" ") or key_str.endswith(" "):
            escaped = key_str.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        return key_str

    def _format_scalar(self, val: Any, indent_level: int = 0) -> str:
        if val is None:
            return "null"
        # In Python, bool subclasses int, must check bool first
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, int):
            return str(val)
        if isinstance(val, float):
            s = str(val)
            return s if ("." in s or "e" in s or "E" in s) else s + ".0"
        if isinstance(val, str):
            if val == "":
                return '""'
            val_lower = val.lower()
            # String scalars that MUST be quoted to prevent boolean/null conversion
            if val_lower in ("true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"):
                return f'"{val}"'
            # Strings looking like numbers must be quoted
            if val.isdigit() or re.fullmatch(r"-?\d+(\.\d+)?([eE][+-]?\d+)?", val):
                return f'"{val}"'
            # Multiline strings: block scalar
            if "\n" in val:
                lines = val.split("\n")
                indent = " " * (self.indent_spaces * (indent_level + 1))
                return "|-\n" + "\n".join(f"{indent}{line}" if line else "" for line in lines)
            # Quote if contains special characters
            if any(c in val for c in '{}[],&*#?|->!%@\\"\':`') or val.startswith(" ") or val.endswith(" ") or val.startswith("- "):
                escaped = val.replace('\\', '\\\\').replace('"', '\\"')
                return f'"{escaped}"'
            return val
        return str(val)

    def _dump_dict(self, d: Dict[str, Any], indent_level: int, lines: List[str], seen: Optional[Set[int]] = None) -> None:
        if seen is None:
            seen = set()
        if not d:
            lines.append(" " * (self.indent_spaces * indent_level) + "{}")
            return

        indent = " " * (self.indent_spaces * indent_level)
        d_id = id(d)
        if d_id in seen or indent_level >= self.max_depth:
            lines.append(f'{indent}"[Truncated: circular reference or max depth reached]"')
            return

        seen.add(d_id)
        try:
            for key, value in d.items():
                k_fmt = self._format_key(key)

                if value is None or isinstance(value, (bool, int, float, str)):
                    fmt_v = self._format_scalar(value, indent_level)
                    if fmt_v.startswith("|-\n"):
                        lines.append(f"{indent}{k_fmt}: {fmt_v}")
                    else:
                        lines.append(f"{indent}{k_fmt}: {fmt_v}")
                elif isinstance(value, dict):
                    if not value:
                        lines.append(f"{indent}{k_fmt}: {{}}")
                    else:
                        lines.append(f"{indent}{k_fmt}:")
                        self._dump_dict(value, indent_level + 1, lines, seen)
                elif isinstance(value, (list, tuple)):
                    if not value:
                        lines.append(f"{indent}{k_fmt}: []")
                    else:
                        lines.append(f"{indent}{k_fmt}:")
                        self._dump_list(value, indent_level + 1, lines, seen)
                else:
                    lines.append(f"{indent}{k_fmt}: {str(value)}")
        finally:
            seen.remove(d_id)

    def _dump_list(self, lst: Union[List[Any], Tuple[Any, ...]], indent_level: int, lines: List[str], seen: Optional[Set[int]] = None) -> None:
        if seen is None:
            seen = set()
        if not lst:
            lines.append(" " * (self.indent_spaces * indent_level) + "[]")
            return

        indent = " " * (self.indent_spaces * indent_level)
        l_id = id(lst)
        if l_id in seen or indent_level >= self.max_depth:
            lines.append(f'{indent}- "[Truncated: circular reference or max depth reached]"')
            return

        seen.add(l_id)
        try:
            for item in lst:
                if item is None or isinstance(item, (bool, int, float, str)):
                    lines.append(f"{indent}- {self._format_scalar(item, indent_level)}")
                elif isinstance(item, dict):
                    if not item:
                        lines.append(f"{indent}- {{}}")
                    else:
                        items_list = list(item.items())
                        first_k, first_v = items_list[0]
                        first_k_fmt = self._format_key(first_k)

                        if first_v is None or isinstance(first_v, (bool, int, float, str)):
                            fmt_v = self._format_scalar(first_v, indent_level + 1)
                            if fmt_v.startswith("|-\n"):
                                lines.append(f"{indent}- {first_k_fmt}: {fmt_v}")
                            else:
                                lines.append(f"{indent}- {first_k_fmt}: {fmt_v}")
                        elif isinstance(first_v, dict):
                            if not first_v:
                                lines.append(f"{indent}- {first_k_fmt}: {{}}")
                            else:
                                lines.append(f"{indent}- {first_k_fmt}:")
                                self._dump_dict(first_v, indent_level + 2, lines, seen)
                        elif isinstance(first_v, (list, tuple)):
                            if not first_v:
                                lines.append(f"{indent}- {first_k_fmt}: []")
                            else:
                                lines.append(f"{indent}- {first_k_fmt}:")
                                self._dump_list(first_v, indent_level + 2, lines, seen)
                        else:
                            lines.append(f"{indent}- {first_k_fmt}: {str(first_v)}")

                        # Subsequent key-value pairs in the same mapping item
                        sub_indent = indent + "  "
                        for k, v in items_list[1:]:
                            k_fmt = self._format_key(k)
                            if v is None or isinstance(v, (bool, int, float, str)):
                                fmt_v = self._format_scalar(v, indent_level + 1)
                                if fmt_v.startswith("|-\n"):
                                    lines.append(f"{sub_indent}{k_fmt}: {fmt_v}")
                                else:
                                    lines.append(f"{sub_indent}{k_fmt}: {fmt_v}")
                            elif isinstance(v, dict):
                                if not v:
                                    lines.append(f"{sub_indent}{k_fmt}: {{}}")
                                else:
                                    lines.append(f"{sub_indent}{k_fmt}:")
                                    self._dump_dict(v, indent_level + 2, lines, seen)
                            elif isinstance(v, (list, tuple)):
                                if not v:
                                    lines.append(f"{sub_indent}{k_fmt}: []")
                                else:
                                    lines.append(f"{sub_indent}{k_fmt}:")
                                    self._dump_list(v, indent_level + 2, lines, seen)
                            else:
                                lines.append(f"{sub_indent}{k_fmt}: {str(v)}")
                elif isinstance(item, (list, tuple)):
                    if not item:
                        lines.append(f"{indent}- []")
                    else:
                        lines.append(f"{indent}-")
                        self._dump_list(item, indent_level + 1, lines, seen)
        finally:
            seen.remove(l_id)


class OpenAPIGenerator:
    """
    OpenAPI 3.1.0 generator.
    Ingests DiscoveredEndpoint models and produces compliant OpenAPI 3.1.0 specs.
    """

    def __init__(
        self,
        endpoints: Optional[Union[List[DiscoveredEndpoint], ScanResult]] = None,
        title: str = "Discovered API",
        version: str = "1.0.0",
        description: Optional[str] = "OpenAPI 3.1.0 specification generated by api-tool",
        servers: Optional[List[str]] = None,
    ):
        self.title = title
        self.version = version
        self.description = description
        self.servers: List[str] = list(servers) if servers else []
        self.endpoints: List[DiscoveredEndpoint] = []
        self.inferrer = OpenAPISchemaInferrer()
        self._cached_spec: Optional[Dict[str, Any]] = None

        if endpoints:
            if isinstance(endpoints, ScanResult):
                self.add_scan_result(endpoints)
            else:
                self.add_endpoints(endpoints)

    def add_endpoint(self, endpoint: DiscoveredEndpoint) -> None:
        """Adds a single DiscoveredEndpoint to the generator."""
        self._cached_spec = None
        self.endpoints.append(endpoint)
        if endpoint.base_url and endpoint.base_url not in self.servers:
            self.servers.append(endpoint.base_url)

    def add_endpoints(self, endpoints: Iterable[DiscoveredEndpoint]) -> None:
        """Adds multiple DiscoveredEndpoints to the generator."""
        for ep in endpoints:
            self.add_endpoint(ep)

    def add_scan_result(self, scan_result: ScanResult) -> None:
        """Ingests endpoints and base URLs from a ScanResult."""
        if scan_result.base_urls:
            for b in scan_result.base_urls:
                if b and b not in self.servers:
                    self.servers.append(b)
        self.add_endpoints(scan_result.endpoints)

    def generate(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Emits 100% compliant OpenAPI 3.1.0 dictionary.
        """
        if not force_refresh and self._cached_spec is not None:
            return self._cached_spec

        spec: Dict[str, Any] = {
            "openapi": "3.1.0",
            "info": {
                "title": self.title,
                "version": self.version,
            },
            "paths": {},
        }

        if self.description:
            spec["info"]["description"] = self.description

        if self.servers:
            spec["servers"] = [{"url": s} for s in self.servers]

        security_schemes: Dict[str, Any] = {}
        paths_map: Dict[str, Dict[str, List[DiscoveredEndpoint]]] = {}

        # Group endpoints by normalized path and HTTP method
        for ep in self.endpoints:
            norm_path, _ = ParameterInferrer.normalize_path(ep.path)
            method = (ep.method or "GET").lower()
            if norm_path not in paths_map:
                paths_map[norm_path] = {}
            if method not in paths_map[norm_path]:
                paths_map[norm_path][method] = []
            paths_map[norm_path][method].append(ep)

        # Build paths
        for norm_path in sorted(paths_map.keys()):
            methods = paths_map[norm_path]
            spec["paths"][norm_path] = {}

            for method in sorted(methods.keys()):
                ep_list = methods[method]
                operation = self._build_operation(norm_path, method, ep_list, security_schemes)
                spec["paths"][norm_path][method] = operation

        if security_schemes:
            spec["components"] = {"securitySchemes": security_schemes}

        self._cached_spec = spec
        return spec

    def _build_operation(
        self,
        norm_path: str,
        method: str,
        ep_list: List[DiscoveredEndpoint],
        security_schemes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Constructs a single OpenAPI operation object."""
        _, path_param_names = ParameterInferrer.normalize_path(norm_path)

        param_dict: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # 1. Mandate all path parameters extracted from path template
        for p_name in path_param_names:
            matched_param: Optional[DiscoveredParameter] = None
            for ep in ep_list:
                for p in ep.parameters:
                    if p.name == p_name and p.location == "path":
                        matched_param = p
                        break
                if matched_param:
                    break

            if matched_param:
                schema = ParameterInferrer.infer_param_schema(p_name, "path", matched_param.example)
                p_obj: Dict[str, Any] = {
                    "name": p_name,
                    "in": "path",
                    "required": True,  # Mandate required: true on all path params
                    "schema": schema,
                }
                if matched_param.description:
                    p_obj["description"] = matched_param.description
                if matched_param.example is not None:
                    p_obj["example"] = matched_param.example
            else:
                schema = ParameterInferrer.infer_param_schema(p_name, "path")
                p_obj = {
                    "name": p_name,
                    "in": "path",
                    "required": True,  # Mandate required: true on all path params
                    "schema": schema,
                    "description": f"Path parameter {p_name}",
                }
            param_dict[(p_name, "path")] = p_obj

        # 2. Query, header, and cookie parameters from discovered endpoints
        for ep in ep_list:
            for p in ep.parameters:
                loc = p.location or "query"
                if loc == "path":
                    # Ensure path param is always marked required
                    if (p.name, "path") in param_dict:
                        param_dict[(p.name, "path")]["required"] = True
                    continue

                if loc in ("query", "header", "cookie"):
                    key = (p.name, loc)
                    if key not in param_dict:
                        schema = ParameterInferrer.infer_param_schema(p.name, loc, p.example)
                        p_obj = {
                            "name": p.name,
                            "in": loc,
                            "required": bool(p.required),
                            "schema": schema,
                        }
                        if p.description:
                            p_obj["description"] = p.description
                        if p.example is not None:
                            p_obj["example"] = p.example
                        param_dict[key] = p_obj
                    else:
                        if p.required:
                            param_dict[key]["required"] = True
                        if p.example is not None and "example" not in param_dict[key]:
                            param_dict[key]["example"] = p.example

        op_params = list(param_dict.values())

        # Metadata
        summary = next((ep.summary for ep in ep_list if ep.summary), f"{method.upper()} {norm_path}")
        description = next((ep.description for ep in ep_list if ep.description), None)
        tags = sorted(list(dict.fromkeys([t for ep in ep_list for t in ep.tags if t])))

        operation: Dict[str, Any] = {}
        if summary:
            operation["summary"] = summary
        if description:
            operation["description"] = description
        if tags:
            operation["tags"] = tags
        if op_params:
            operation["parameters"] = op_params

        # 3. Request body handling for POST/PUT/PATCH/DELETE
        if method in ("post", "put", "patch", "delete"):
            body_schema: Optional[Dict[str, Any]] = None
            for ep in ep_list:
                if ep.request_body_schema:
                    if body_schema is None:
                        body_schema = copy.deepcopy(ep.request_body_schema)
                    else:
                        body_schema = self.inferrer.merge(body_schema, ep.request_body_schema)
                elif ep.request_body_sample is not None:
                    inferred = self.inferrer.infer(ep.request_body_sample)
                    if body_schema is None:
                        body_schema = inferred
                    else:
                        body_schema = self.inferrer.merge(body_schema, inferred)

            # Check body parameters if still no schema
            if body_schema is None:
                body_props: Dict[str, Any] = {}
                body_req: List[str] = []
                for ep in ep_list:
                    for p in ep.parameters:
                        if p.location == "body":
                            body_props[p.name] = ParameterInferrer.infer_param_schema(p.name, "body", p.example)
                            if p.required:
                                body_req.append(p.name)
                if body_props:
                    body_schema = {"type": "object", "properties": body_props}
                    if body_req:
                        body_schema["required"] = sorted(list(set(body_req)))

            if body_schema is not None:
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": body_schema,
                        }
                    },
                }

        # 4. Responses: at least default or active_status response, never empty
        responses: Dict[str, Any] = {}
        for ep in ep_list:
            for resp in ep.responses:
                code_str = str(resp.status_code)
                schema: Optional[Dict[str, Any]] = None
                if resp.inferred_schema:
                    schema = copy.deepcopy(resp.inferred_schema)
                elif resp.sample_body is not None:
                    schema = self.inferrer.infer(resp.sample_body)

                ct = resp.content_type or "application/json"
                if code_str not in responses:
                    desc = "Successful operation" if 200 <= resp.status_code < 300 else f"HTTP {resp.status_code} response"
                    resp_obj: Dict[str, Any] = {"description": desc}
                    if schema:
                        resp_obj["content"] = {ct: {"schema": schema}}
                    responses[code_str] = resp_obj
                else:
                    if schema:
                        if "content" not in responses[code_str]:
                            responses[code_str]["content"] = {ct: {"schema": schema}}
                        elif ct not in responses[code_str]["content"]:
                            responses[code_str]["content"][ct] = {"schema": schema}
                        else:
                            curr_schema = responses[code_str]["content"][ct].get("schema", {})
                            responses[code_str]["content"][ct]["schema"] = self.inferrer.merge(
                                curr_schema, schema
                            )

            if ep.active_status is not None:
                active_str = str(ep.active_status)
                if active_str not in responses:
                    desc = "Successful operation" if 200 <= ep.active_status < 300 else f"HTTP {ep.active_status} response"
                    responses[active_str] = {"description": desc}

        if not responses:
            responses["200"] = {
                "description": "Successful operation"
            }

        operation["responses"] = responses

        # 5. Security schemes
        op_security: List[Dict[str, List[str]]] = []
        for ep in ep_list:
            if ep.auth_type:
                atype = ep.auth_type.lower().strip()
                if atype in ("bearer", "jwt"):
                    scheme_name = "bearerAuth"
                    if scheme_name not in security_schemes:
                        security_schemes[scheme_name] = {
                            "type": "http",
                            "scheme": "bearer",
                            "bearerFormat": "JWT",
                        }
                    sec_entry = {scheme_name: []}
                    if sec_entry not in op_security:
                        op_security.append(sec_entry)
                elif atype in ("apikey", "api_key"):
                    scheme_name = "apiKeyAuth"
                    header_name = ep.auth_header_or_param or "X-API-Key"
                    if scheme_name not in security_schemes:
                        security_schemes[scheme_name] = {
                            "type": "apiKey",
                            "name": header_name,
                            "in": "header",
                        }
                    sec_entry = {scheme_name: []}
                    if sec_entry not in op_security:
                        op_security.append(sec_entry)
                elif atype == "basic":
                    scheme_name = "basicAuth"
                    if scheme_name not in security_schemes:
                        security_schemes[scheme_name] = {
                            "type": "http",
                            "scheme": "basic",
                        }
                    sec_entry = {scheme_name: []}
                    if sec_entry not in op_security:
                        op_security.append(sec_entry)
                elif atype == "oauth2":
                    scheme_name = "oauth2"
                    if scheme_name not in security_schemes:
                        security_schemes[scheme_name] = {
                            "type": "oauth2",
                            "flows": {
                                "clientCredentials": {
                                    "tokenUrl": "/oauth/token",
                                    "scopes": {},
                                }
                            },
                        }
                    sec_entry = {scheme_name: []}
                    if sec_entry not in op_security:
                        op_security.append(sec_entry)

        if op_security:
            operation["security"] = op_security

        return operation

    def to_json(self, indent: int = 2) -> str:
        """Renders the OpenAPI 3.1.0 specification as a JSON string."""
        return json.dumps(self.generate(), indent=indent)

    def to_yaml(self) -> str:
        """Renders the OpenAPI 3.1.0 specification as a YAML string using PureYamlDumper."""
        return PureYamlDumper.dump(self.generate())

    def export_file(self, output_path: str, format: str = "json") -> str:
        """
        Exports the generated OpenAPI specification to a file in json or yaml format.
        Creates parent directories if necessary.
        """
        fmt = (format or "json").lower().strip()
        if fmt in ("yaml", "yml"):
            content = self.to_yaml()
        else:
            content = self.to_json()

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return content
