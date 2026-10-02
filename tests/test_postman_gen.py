"""
Comprehensive unit tests for api_tool.exporter.postman_gen.
Tests:
1. Domain Dataclasses (PostmanVariable, PostmanHeader, PostmanQueryParam, PostmanPathVariable,
   PostmanUrl, PostmanBody, PostmanRequest, PostmanItem, PostmanCollection).
2. Trie / Radix FolderTree algorithm:
   - Endpoint tag prioritization.
   - Common prefix flattening/compaction ('api/v1' into 'api/v1/Users').
   - Truncation at parameter boundaries (never creates folder named ':id').
   - Single-segment root routes (/health, /ping) placed directly in root items.
3. Modern Framework Support:
   - Next.js 14/15 Server Actions: POST, Next-Action header, Accept: text/x-component, body.
   - GraphQL Operations: POST, GraphQL endpoint, mode: 'graphql', dedicated 'GraphQL' folder.
4. Compatibility Rules:
   - Schema version 2.1.0.
   - url.raw fully formed with {{baseUrl}}.
   - Path parameters use colon syntax :param in raw and path, and listed in url.variable.
   - to_dict, to_json, export_file methods.
5. Postman, Bruno, and Insomnia schema import compatibility verification.
"""

import json
import os
import tempfile
import unittest
import uuid

from api_tool.exporter.postman_gen import (
    PostmanVariable,
    PostmanHeader,
    PostmanQueryParam,
    PostmanPathVariable,
    PostmanUrl,
    PostmanBody,
    PostmanRequest,
    PostmanItem,
    PostmanCollection,
    FolderTree,
    PostmanCollectionExporter,
    build_postman_url,
    generate_postman_collection,
    export_postman_collection,
    POSTMAN_V21_SCHEMA,
)
from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    GraphQLOperation,
    ScanResult,
)


class TestPostmanDomainDataclasses(unittest.TestCase):
    """Verifies all domain dataclasses match the required specifications."""

    def test_postman_variable_defaults_and_types(self):
        v = PostmanVariable(key="apiKey")
        self.assertEqual(v.key, "apiKey")
        self.assertEqual(v.value, "")
        self.assertEqual(v.type, "string")
        self.assertIsNone(v.description)

        d = v.to_dict()
        self.assertEqual(d["key"], "apiKey")
        self.assertEqual(d["value"], "")
        self.assertEqual(d["type"], "string")
        self.assertNotIn("description", d)

        v2 = PostmanVariable(key="port", value="8080", type="number", description="Port number")
        d2 = v2.to_dict()
        self.assertEqual(d2["key"], "port")
        self.assertEqual(d2["value"], "8080")
        self.assertEqual(d2["description"], "Port number")

    def test_postman_header_strict_strings_and_disabled(self):
        # Strict string casting for non-string input
        h = PostmanHeader(key="X-Count", value=100)  # type: ignore
        self.assertIsInstance(h.key, str)
        self.assertIsInstance(h.value, str)
        self.assertEqual(h.value, "100")
        self.assertEqual(h.type, "text")
        self.assertFalse(h.disabled)

        d = h.to_dict()
        self.assertEqual(d["key"], "X-Count")
        self.assertEqual(d["value"], "100")
        self.assertNotIn("disabled", d)

        h_disabled = PostmanHeader(key="Authorization", value="Bearer secret", disabled=True)
        d_disabled = h_disabled.to_dict()
        self.assertTrue(d_disabled["disabled"])

    def test_postman_query_param(self):
        qp = PostmanQueryParam(key="search", value="term", description="Query keyword")
        d = qp.to_dict()
        self.assertEqual(d["key"], "search")
        self.assertEqual(d["value"], "term")
        self.assertEqual(d["description"], "Query keyword")
        self.assertNotIn("disabled", d)

        qp_disabled = PostmanQueryParam(key="limit", value="10", disabled=True)
        self.assertTrue(qp_disabled.to_dict()["disabled"])

    def test_postman_path_variable_colon_stripping(self):
        pv1 = PostmanPathVariable(key="userId", value="42", description="User identifier")
        self.assertEqual(pv1.key, "userId")
        d1 = pv1.to_dict()
        self.assertEqual(d1["key"], "userId")
        self.assertEqual(d1["value"], "42")
        self.assertEqual(d1["description"], "User identifier")

        # Leading colon must be stripped in variable key for Postman schema matching
        pv2 = PostmanPathVariable(key=":orderId")
        self.assertEqual(pv2.key, "orderId")
        self.assertEqual(pv2.to_dict()["key"], "orderId")

    def test_postman_url_structure(self):
        url = PostmanUrl(
            raw="{{baseUrl}}/api/v1/users/:id?page=1",
            host=["{{baseUrl}}"],
            path=["api", "v1", "users", ":id"],
            query=[PostmanQueryParam(key="page", value="1")],
            variable=[PostmanPathVariable(key="id", value="123")],
        )
        d = url.to_dict()
        self.assertEqual(d["raw"], "{{baseUrl}}/api/v1/users/:id?page=1")
        self.assertEqual(d["host"], ["{{baseUrl}}"])
        self.assertEqual(d["path"], ["api", "v1", "users", ":id"])
        self.assertEqual(d["query"][0]["key"], "page")
        self.assertEqual(d["variable"][0]["key"], "id")

    def test_postman_body_modes(self):
        # Raw JSON mode
        b_raw = PostmanBody(mode="raw", raw='{"success": true}', language="json")
        d_raw = b_raw.to_dict()
        self.assertEqual(d_raw["mode"], "raw")
        self.assertEqual(d_raw["raw"], '{"success": true}')
        self.assertEqual(d_raw["options"]["raw"]["language"], "json")

        # GraphQL mode (dict variables serialized to string)
        b_gql = PostmanBody(
            mode="graphql",
            graphql={"query": "query { hello }", "variables": {"id": 1}},
        )
        d_gql = b_gql.to_dict()
        self.assertEqual(d_gql["mode"], "graphql")
        self.assertEqual(d_gql["graphql"]["query"], "query { hello }")
        self.assertIn('"id": 1', d_gql["graphql"]["variables"])

        # Formdata mode
        b_form = PostmanBody(
            mode="formdata",
            formdata=[{"key": "file", "value": "test.txt", "type": "text"}],
        )
        d_form = b_form.to_dict()
        self.assertEqual(d_form["mode"], "formdata")
        self.assertEqual(len(d_form["formdata"]), 1)

    def test_postman_request_method_normalization(self):
        req = PostmanRequest(
            method="post",
            url=PostmanUrl(raw="{{baseUrl}}/items"),
            header=[PostmanHeader(key="Content-Type", value="application/json")],
        )
        self.assertEqual(req.method, "POST")
        d = req.to_dict()
        self.assertEqual(d["method"], "POST")
        self.assertEqual(d["url"]["raw"], "{{baseUrl}}/items")

    def test_postman_item_leaf_and_folder(self):
        # Leaf item
        req = PostmanRequest(method="GET", url=PostmanUrl(raw="{{baseUrl}}/ping"))
        leaf = PostmanItem(name="Ping", request=req)
        d_leaf = leaf.to_dict()
        self.assertEqual(d_leaf["name"], "Ping")
        self.assertIn("request", d_leaf)
        self.assertNotIn("item", d_leaf)

        # Folder item
        folder = PostmanItem(name="Utilities", item=[leaf])
        d_folder = folder.to_dict()
        self.assertEqual(d_folder["name"], "Utilities")
        self.assertIn("item", d_folder)
        self.assertEqual(len(d_folder["item"]), 1)
        self.assertNotIn("request", d_folder)

    def test_postman_collection_structure_and_export(self):
        col = PostmanCollection(
            name="My Test API",
            description="API collection for unit testing",
        )
        self.assertEqual(col.schema, POSTMAN_V21_SCHEMA)
        self.assertTrue(uuid.UUID(col.id))

        d = col.to_dict()
        self.assertEqual(d["info"]["name"], "My Test API")
        self.assertEqual(d["info"]["schema"], POSTMAN_V21_SCHEMA)
        self.assertEqual(d["info"]["_postman_id"], col.id)
        # Ensure default baseUrl variable is automatically injected
        self.assertEqual(d["variable"][0]["key"], "baseUrl")

        # Test to_json
        json_str = col.to_json(indent=2)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["info"]["name"], "My Test API")

        # Test export_file
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "subdir", "collection.json")
            res_path = col.export_file(out_file)
            self.assertTrue(os.path.exists(res_path))
            with open(res_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(saved["info"]["name"], "My Test API")


class TestUrlBuildingAndCompatibility(unittest.TestCase):
    """Verifies Postman URL generation, parameter normalization, and {{baseUrl}} adherence."""

    def test_openapi_brace_parameters_normalization(self):
        url = build_postman_url(
            "/api/v1/users/{userId}/posts/{postId}",
            parameters=[
                DiscoveredParameter(name="userId", location="path", example="42", description="User ID"),
                DiscoveredParameter(name="postId", location="path", example="999", description="Post ID"),
            ],
        )
        self.assertEqual(url.raw, "{{baseUrl}}/api/v1/users/:userId/posts/:postId")
        self.assertEqual(url.path, ["api", "v1", "users", ":userId", "posts", ":postId"])
        self.assertEqual(len(url.variable), 2)
        self.assertEqual(url.variable[0].key, "userId")
        self.assertEqual(url.variable[0].value, "42")
        self.assertEqual(url.variable[1].key, "postId")
        self.assertEqual(url.variable[1].value, "999")

    def test_django_flask_angle_bracket_parameters(self):
        url = build_postman_url("/items/<item_id>")
        self.assertEqual(url.raw, "{{baseUrl}}/items/:item_id")
        self.assertEqual(url.path, ["items", ":item_id"])
        self.assertEqual(url.variable[0].key, "item_id")

    def test_query_params_in_url_and_parameters_list(self):
        url = build_postman_url(
            "/search?q=test&limit=10",
            parameters=[
                DiscoveredParameter(name="page", location="query", example="2", description="Page number"),
            ],
        )
        self.assertTrue(url.raw.startswith("{{baseUrl}}/search?"))
        self.assertIn("q=test", url.raw)
        self.assertIn("limit=10", url.raw)
        self.assertIn("page=2", url.raw)
        keys = [qp.key for qp in url.query]
        self.assertIn("q", keys)
        self.assertIn("limit", keys)
        self.assertIn("page", keys)

    def test_full_url_input_host_stripping(self):
        url = build_postman_url("https://external-api.com/v1/metrics")
        self.assertEqual(url.raw, "{{baseUrl}}/v1/metrics")
        self.assertEqual(url.path, ["v1", "metrics"])


class TestFolderTreeAlgorithm(unittest.TestCase):
    """Verifies the Trie / Radix folder organization algorithm."""

    def test_single_segment_root_routes_remain_at_root(self):
        tree = FolderTree()
        ep_health = DiscoveredEndpoint(path="/health", method="GET")
        ep_ping = DiscoveredEndpoint(path="/ping", method="GET")
        ep_root = DiscoveredEndpoint(path="/", method="GET")
        ep_users = DiscoveredEndpoint(path="/users/:id", method="GET")

        tree.add_endpoint(ep_health)
        tree.add_endpoint(ep_ping)
        tree.add_endpoint(ep_root)
        tree.add_endpoint(ep_users)

        items = tree.build()
        root_names = [it.name for it in items if it.request is not None]
        folder_names = [it.name for it in items if it.item is not None]

        self.assertIn("GET /health", root_names)
        self.assertIn("GET /ping", root_names)
        self.assertIn("GET /", root_names)
        self.assertIn("Users", folder_names)

    def test_parameter_boundary_truncation_never_creates_param_folder(self):
        tree = FolderTree()
        ep1 = DiscoveredEndpoint(path="/users", method="GET")
        ep2 = DiscoveredEndpoint(path="/users/:id", method="GET")
        ep3 = DiscoveredEndpoint(path="/users/:id/details", method="GET")
        ep4 = DiscoveredEndpoint(path="/organizations/{orgId}/projects/{projId}", method="GET")

        tree.add_endpoint(ep1)
        tree.add_endpoint(ep2)
        tree.add_endpoint(ep3)
        tree.add_endpoint(ep4)

        items = tree.build()
        folder_names = [it.name for it in items if it.item is not None]

        # Both /users and /users/:id must live under 'Users'
        self.assertIn("Users", folder_names)
        self.assertIn("Organizations", folder_names)

        # Ensure NO folder named ':id', '{orgId}', or ':projId' is created
        for f in folder_names:
            self.assertFalse(f.startswith(":"), f"Folder should never start with colon: {f}")
            self.assertFalse("{" in f, f"Folder should never have braces: {f}")

        # Check endpoints inside Users folder
        users_folder = next(it for it in items if it.name == "Users")
        self.assertEqual(len(users_folder.item), 3)

    def test_prefix_compaction_flattens_common_api_v1(self):
        tree = FolderTree(flatten_prefixes=True)
        ep1 = DiscoveredEndpoint(path="/api/v1/users", method="GET")
        ep2 = DiscoveredEndpoint(path="/api/v1/users/:id", method="GET")
        ep3 = DiscoveredEndpoint(path="/api/v1/billing", method="GET", tags=["Billing"])
        ep4 = DiscoveredEndpoint(path="/health", method="GET")

        tree.add_endpoint(ep1)
        tree.add_endpoint(ep2)
        tree.add_endpoint(ep3)
        tree.add_endpoint(ep4)

        items = tree.build()
        folder_names = [it.name for it in items if it.item is not None]

        # Common prefix 'api/v1' compacted into 'api/v1/Users' and 'api/v1/Billing'
        self.assertIn("api/v1/Users", folder_names)
        self.assertIn("api/v1/Billing", folder_names)

        # /health left in root items
        root_req_names = [it.name for it in items if it.request is not None]
        self.assertIn("GET /health", root_req_names)

    def test_endpoint_tag_prioritization(self):
        tree = FolderTree()
        # Endpoint path is /v1/account/payment, but tagged 'Billing'
        ep = DiscoveredEndpoint(
            path="/v1/account/payment",
            method="POST",
            tags=["Billing"],
        )
        tree.add_endpoint(ep)

        items = tree.build()
        folder_names = [it.name for it in items if it.item is not None]
        self.assertIn("v1/Billing", folder_names)


class TestModernFrameworkSupport(unittest.TestCase):
    """Verifies Next.js 14/15 Server Actions and GraphQL Operation handling."""

    def test_nextjs_server_action_headers_and_body(self):
        action_id = "40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f"
        ep = DiscoveredEndpoint(
            path="/dashboard",
            method="POST",
            headers={"Next-Action": action_id},
            tags=["server_action", "nextjs"],
            summary=f"Next.js Server Action: {action_id}",
        )

        col = generate_postman_collection(endpoints=[ep])
        dashboard_folder = col.items[0]
        self.assertEqual(dashboard_folder.name, "Dashboard")
        item = dashboard_folder.item[0]

        # Verify POST request
        self.assertEqual(item.request.method, "POST")
        headers = {h.key: h.value for h in item.request.header}

        # Verify Next-Action and Accept: text/x-component headers
        self.assertEqual(headers.get("Next-Action"), action_id)
        self.assertEqual(headers.get("Accept"), "text/x-component")

        # Verify body
        self.assertEqual(item.request.body.mode, "raw")
        self.assertEqual(item.request.body.raw, '["$K1"]')

    def test_nextjs_server_action_formdata_support(self):
        action_id = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        ep = DiscoveredEndpoint(
            path="/profile",
            method="POST",
            headers={"Next-Action": action_id},
            tags=["server_action"],
            parameters=[
                DiscoveredParameter(name="username", location="formData", example="alice"),
            ],
        )

        col = generate_postman_collection(endpoints=[ep])
        item = col.items[0].item[0]
        self.assertEqual(item.request.body.mode, "formdata")
        self.assertEqual(item.request.body.formdata[0]["key"], "username")
        self.assertEqual(item.request.body.formdata[0]["value"], "alice")

    def test_graphql_dedicated_folder_and_mode(self):
        gql_query = "query GetUser($id: ID!) { user(id: $id) { name email } }"
        gql_op = GraphQLOperation(
            operation_type="query",
            operation_name="GetUser",
            query_string=gql_query,
            endpoint="/api/graphql",
            variables_sample={"id": "user_42"},
        )

        col = generate_postman_collection(graphql_operations=[gql_op])
        self.assertEqual(len(col.items), 1)

        gql_folder = col.items[0]
        self.assertEqual(gql_folder.name, "GraphQL")
        self.assertEqual(len(gql_folder.item), 1)

        op_item = gql_folder.item[0]
        self.assertEqual(op_item.name, "GetUser (query)")
        self.assertEqual(op_item.request.method, "POST")
        self.assertEqual(op_item.request.url.raw, "{{baseUrl}}/api/graphql")

        # Verify GraphQL body mode
        body = op_item.request.body
        self.assertEqual(body.mode, "graphql")
        self.assertEqual(body.graphql["query"], gql_query)
        self.assertIn('"user_42"', body.graphql["variables"])


class TestPostmanScanResultIntegration(unittest.TestCase):
    """End-to-end integration tests using full ScanResult model."""

    def test_full_scan_result_export_and_json_validity(self):
        scan_res = ScanResult(
            target_url="https://api.mycorp.internal",
            base_urls=["https://api.mycorp.internal/v1"],
            endpoints=[
                DiscoveredEndpoint(path="/health", method="GET"),
                DiscoveredEndpoint(
                    path="/api/v1/users",
                    method="GET",
                    tags=["Users"],
                    parameters=[DiscoveredParameter(name="page", location="query", example="1")],
                ),
                DiscoveredEndpoint(
                    path="/api/v1/users/{id}",
                    method="PUT",
                    tags=["Users"],
                    parameters=[DiscoveredParameter(name="id", location="path", example="5")],
                    request_body_sample={"name": "Alice"},
                ),
            ],
            graphql_operations=[
                GraphQLOperation(
                    operation_type="mutation",
                    operation_name="CreateInvoice",
                    query_string="mutation CreateInvoice { createInvoice { id } }",
                    endpoint="/graphql",
                )
            ],
        )

        col = generate_postman_collection(scan_result=scan_res)
        d = col.to_dict()

        # Check collection info
        self.assertEqual(d["info"]["schema"], POSTMAN_V21_SCHEMA)
        self.assertIn("api.mycorp.internal", d["info"]["name"])

        # Check variable baseUrl resolves from base_urls
        base_url_var = next(v for v in d["variable"] if v["key"] == "baseUrl")
        self.assertEqual(base_url_var["value"], "https://api.mycorp.internal/v1")

        # Verify item count: 1 root route (/health) + 1 Users folder + 1 GraphQL folder
        item_names = [it["name"] for it in d["item"]]
        self.assertIn("GET /health", item_names)
        self.assertIn("api/v1/Users", item_names)
        self.assertIn("GraphQL", item_names)

        # Verify export_postman_collection helper writes valid JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "export.json")
            written_path = export_postman_collection(scan_result=scan_res, output_path=file_path)
            self.assertEqual(written_path, file_path)

            with open(file_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)

            self.assertEqual(loaded["info"]["schema"], POSTMAN_V21_SCHEMA)


class TestCompatibilityRulesAndToolImporters(unittest.TestCase):
    """
    Verifies strict zero-error import compatibility with:
    - Postman Collection v2.1.0 JSON Schema
    - Bruno CLI & GUI Postman v2.1 Importer
    - Insomnia REST Client Postman v2.1 Importer
    """

    def setUp(self):
        self.scan_res = ScanResult(
            target_url="https://api.acme.corp",
            base_urls=["https://api.acme.corp/v1"],
            endpoints=[
                DiscoveredEndpoint(path="/health", method="GET"),
                DiscoveredEndpoint(path="/metrics", method="GET"),
                DiscoveredEndpoint(
                    path="/api/v1/users",
                    method="GET",
                    tags=["Users"],
                    parameters=[
                        DiscoveredParameter(name="role", location="query", example="admin"),
                        DiscoveredParameter(name="limit", location="query", example="50"),
                    ],
                ),
                DiscoveredEndpoint(
                    path="/api/v1/users/{userId}/sessions/:sessionId",
                    method="DELETE",
                    tags=["Users"],
                    parameters=[
                        DiscoveredParameter(name="userId", location="path", example="usr_123"),
                        DiscoveredParameter(name="sessionId", location="path", example="sess_999"),
                    ],
                ),
                DiscoveredEndpoint(
                    path="/api/v1/billing/invoices",
                    method="POST",
                    tags=["Billing"],
                    request_body_sample={"amount": 4999, "currency": "USD"},
                    headers={"X-Idempotency-Key": "idem_abc123"},
                    auth_type="bearer",
                ),
                DiscoveredEndpoint(
                    path="/dashboard",
                    method="POST",
                    headers={"Next-Action": "c8f2a1b3d4e5f60718293a4b5c6d7e8f90123456"},
                    tags=["server_action", "nextjs"],
                    summary="Next.js Server Action: c8f2a1b3d4e5f60718293a4b5c6d7e8f90123456",
                ),
            ],
            graphql_operations=[
                GraphQLOperation(
                    operation_type="query",
                    operation_name="ListProducts",
                    query_string="query ListProducts($category: String!) { products(category: $category) { id name price } }",
                    endpoint="/graphql",
                    variables_sample={"category": "electronics"},
                ),
                GraphQLOperation(
                    operation_type="subscription",
                    operation_name="OnOrderCreated",
                    query_string="subscription OnOrderCreated { orderCreated { id total } }",
                    endpoint="/graphql",
                ),
            ],
        )
        self.collection = generate_postman_collection(scan_result=self.scan_res)
        self.collection_dict = self.collection.to_dict()

    def test_schema_string_exact_match(self):
        """Rule: schema must be 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'"""
        self.assertEqual(
            self.collection_dict["info"]["schema"],
            "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        )

    def test_url_raw_always_starts_with_base_url(self):
        """Rule: url.raw must ALWAYS be provided and fully formed with {{baseUrl}}"""
        def check_requests(items):
            for it in items:
                if "request" in it:
                    raw_url = it["request"]["url"]["raw"]
                    self.assertIsInstance(raw_url, str)
                    self.assertTrue(
                        raw_url.startswith("{{baseUrl}}"),
                        f"URL raw '{raw_url}' must start with '{{{{baseUrl}}}}'",
                    )
                if "item" in it:
                    check_requests(it["item"])

        check_requests(self.collection_dict["item"])

    def test_path_parameters_colon_syntax_and_variable_listing(self):
        """Rule: Path parameters must use colon syntax :id in raw and path, and be listed in url.variable."""
        def check_items(items):
            for it in items:
                if "request" in it:
                    req = it["request"]
                    url = req["url"]
                    raw = url["raw"]
                    path_segments = url.get("path", [])
                    variables = url.get("variable", [])

                    # No un-normalized {param} or <param> in raw or path segments (excluding {{baseUrl}})
                    raw_after_base = raw.replace("{{baseUrl}}", "")
                    self.assertFalse("{" in raw_after_base or "}" in raw_after_base, f"Found curly braces in raw url: {raw}")
                    self.assertFalse("<" in raw or ">" in raw, f"Found angle brackets in raw url: {raw}")
                    for seg in path_segments:
                        self.assertFalse("{" in seg or "}" in seg, f"Found curly braces in segment: {seg}")
                        self.assertFalse("<" in seg or ">" in seg, f"Found angle brackets in segment: {seg}")

                    # Any segment starting with colon must have corresponding variable
                    colon_params = [seg.lstrip(":") for seg in path_segments if seg.startswith(":")]
                    var_keys = [v["key"] for v in variables]
                    for cp in colon_params:
                        self.assertIn(
                            cp,
                            var_keys,
                            f"Path parameter ':{cp}' in path {path_segments} not found in url.variable {var_keys}",
                        )

                if "item" in it:
                    check_items(it["item"])

        check_items(self.collection_dict["item"])

    def test_bruno_importer_compatibility(self):
        """
        Simulates the Bruno Postman Collection importer:
        - info.name
        - collection variables
        - recursive item traversal
        - request method, url.raw, headers, body modes (raw, graphql)
        """
        d = self.collection_dict
        self.assertIn("name", d["info"])
        self.assertIn("variable", d)
        self.assertIsInstance(d["variable"], list)

        # Bruno reads collection variables:
        vars_map = {v["key"]: v["value"] for v in d["variable"]}
        self.assertIn("baseUrl", vars_map)

        # Recursive parsing simulation
        flattened_requests = []

        def traverse(items, current_folder=""):
            for it in items:
                if "request" in it:
                    req = it["request"]
                    # Bruno requires method string
                    method = req["method"]
                    self.assertIn(method, ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])

                    # Bruno requires url raw
                    raw = req["url"]["raw"]
                    self.assertTrue(len(raw) > 0)

                    # Bruno headers parser requires key and value as strings
                    headers = req.get("header", [])
                    for h in headers:
                        self.assertIsInstance(h["key"], str)
                        self.assertIsInstance(h["value"], str)

                    # Bruno body parser
                    body = req.get("body")
                    if body:
                        mode = body.get("mode")
                        self.assertIn(mode, ["raw", "graphql", "formdata", "urlencoded"])
                        if mode == "graphql":
                            self.assertIn("query", body["graphql"])
                            self.assertIsInstance(body["graphql"]["variables"], str)

                    flattened_requests.append((current_folder, it["name"], method, raw))
                elif "item" in it:
                    folder_path = f"{current_folder}/{it['name']}" if current_folder else it["name"]
                    traverse(it["item"], folder_path)

        traverse(d["item"])
        self.assertTrue(len(flattened_requests) >= 6)

    def test_insomnia_importer_compatibility(self):
        """
        Simulates the Insomnia Postman Collection importer:
        - validates info.schema v2.1.0
        - checks {{baseUrl}} variable resolution
        - verifies path variables translation
        """
        d = self.collection_dict
        schema = d["info"]["schema"]
        self.assertIn("v2.1.0", schema)

        # Check variable declaration
        has_base_url = any(v["key"] == "baseUrl" for v in d["variable"])
        self.assertTrue(has_base_url)

        # Insomnia translates colon parameters like :userId to its internal model
        found_session_endpoint = False
        for it in d["item"]:
            if it.get("name") == "api/v1/Users":
                for sub in it.get("item", []):
                    if "sessions/:sessionId" in sub["request"]["url"]["raw"]:
                        found_session_endpoint = True
                        req = sub["request"]
                        self.assertEqual(req["method"], "DELETE")
                        var_keys = [v["key"] for v in req["url"]["variable"]]
                        self.assertIn("userId", var_keys)
                        self.assertIn("sessionId", var_keys)

        self.assertTrue(found_session_endpoint)


class TestFolderTreeAdvancedCompaction(unittest.TestCase):
    """Verifies edge cases in prefix compaction, multi-level routes, and tag overrides."""

    def test_deep_nesting_truncated_at_first_parameter(self):
        tree = FolderTree()
        ep = DiscoveredEndpoint(
            path="/api/v1/orgs/{orgId}/teams/{teamId}/repos/{repoId}/commits",
            method="GET",
        )
        tree.add_endpoint(ep)
        items = tree.build()

        self.assertEqual(len(items), 1)
        folder = items[0]
        # Common prefix api/v1 + Orgs -> api/v1/Orgs
        self.assertEqual(folder.name, "api/v1/Orgs")

        # Item request URL must retain all parameters
        it = folder.item[0]
        self.assertIn(":orgId", it.request.url.raw)
        self.assertIn(":teamId", it.request.url.raw)
        self.assertIn(":repoId", it.request.url.raw)
        var_keys = [v.key for v in it.request.url.variable]
        self.assertEqual(var_keys, ["orgId", "teamId", "repoId"])

    def test_tag_overrides_path_structure(self):
        tree = FolderTree(flatten_prefixes=False)
        ep = DiscoveredEndpoint(
            path="/internal/v3/legacy/export/data",
            method="POST",
            tags=["Reporting"],
        )
        tree.add_endpoint(ep)
        items = tree.build()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "Reporting")

    def test_custom_root_routes_registration(self):
        tree = FolderTree(root_route_names={"myhealth", "customping"})
        ep1 = DiscoveredEndpoint(path="/myhealth", method="GET")
        ep2 = DiscoveredEndpoint(path="/customping", method="GET")
        tree.add_endpoint(ep1)
        tree.add_endpoint(ep2)
        items = tree.build()

        # Both should be at root
        for it in items:
            self.assertIsNotNone(it.request)
            self.assertIsNone(it.item)


if __name__ == "__main__":
    unittest.main()

