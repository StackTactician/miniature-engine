"""
Unit tests for api_tool.analyzer.apq_extractor and GraphQL APQ Probing.

Tests:
1. PersistedQueryRecord dataclass, to_dict, and from_dict serialization.
2. calculate_sha256 Apollo AST normalization and SHA-256 calculation.
3. Apollo APQ hash extraction from client code, AST objects, and URL parameters.
4. Relay persisted query extraction (doc_id, id, ConcreteRequest params).
5. JS bundle manifest dictionaries ({ id: "...", text: "..." } and { "<hash>": "query..." }).
6. Apollo Persisted Query Manifest (format: apollo-persisted-query-manifest).
7. Network HAR log extraction for APQ parameters in GET and POST requests.
8. SDL Synthesis from persisted queries using graphql-core without __schema introspection.
9. Type and field merging across multiple queries, mutations, and subscriptions.
10. Variable argument type propagation, custom input/scalar declaration, and fragment expansion.
11. GraphQLProber.probe_apq_hash with mock transport (data execution and PersistedQueryNotFound acknowledgement).
"""

import json
import unittest
import httpx
from graphql import build_schema

from api_tool.analyzer.apq_extractor import (
    APQOperationExtractor,
    calculate_sha256,
    synthesize_sdl_from_records,
)
from api_tool.models import PersistedQueryRecord
from api_tool.prober.graphql_prober import GraphQLProber, GraphQLProbeResult


class TestPersistedQueryRecord(unittest.TestCase):
    def test_record_instantiation_and_defaults(self):
        rec = PersistedQueryRecord(sha256_hash="a" * 64)
        self.assertEqual(rec.sha256_hash, "a" * 64)
        self.assertIsNone(rec.operation_name)
        self.assertIsNone(rec.query_string)
        self.assertEqual(rec.source, "apq_manifest")

    def test_to_dict_and_from_dict(self):
        rec = PersistedQueryRecord(
            sha256_hash="b" * 64,
            operation_name="GetUser",
            query_string="query GetUser { user { id } }",
            source="bundle_ast",
        )
        d = rec.to_dict()
        self.assertEqual(d["sha256_hash"], "b" * 64)
        self.assertEqual(d["operation_name"], "GetUser")
        self.assertEqual(d["source"], "bundle_ast")

        restored = PersistedQueryRecord.from_dict(d)
        self.assertEqual(restored.sha256_hash, rec.sha256_hash)
        self.assertEqual(restored.operation_name, rec.operation_name)
        self.assertEqual(restored.query_string, rec.query_string)
        self.assertEqual(restored.source, rec.source)

    def test_from_dict_aliases(self):
        # Apollo manifest aliases
        d1 = {"sha256Hash": "c" * 64, "name": "Profile", "body": "query Profile { me { id } }"}
        r1 = PersistedQueryRecord.from_dict(d1)
        self.assertEqual(r1.sha256_hash, "c" * 64)
        self.assertEqual(r1.operation_name, "Profile")
        self.assertIn("me { id }", r1.query_string)

        # Relay aliases
        d2 = {"id": "relay-id-123", "operationName": "RelayOp", "text": "query RelayOp { node { id } }"}
        r2 = PersistedQueryRecord.from_dict(d2)
        self.assertEqual(r2.sha256_hash, "relay-id-123")
        self.assertEqual(r2.operation_name, "RelayOp")


class TestCalculateSHA256(unittest.TestCase):
    def test_sha256_calculation(self):
        query = "query GetUser { user { id name } }"
        h = calculate_sha256(query)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)

    def test_ast_normalization_produces_consistent_hash(self):
        # Queries with comments and varied whitespace normalize to identical AST and hash
        q1 = """
        query GetUserProfile {
          user {
            id
            name
          }
        }
        """
        q2 = "query GetUserProfile {\n  # Fetch user profile\n  user {\n    id\n    name\n  }\n}"
        q3 = "query GetUserProfile { user { id name } }"

        h1 = calculate_sha256(q1)
        h2 = calculate_sha256(q2)
        h3 = calculate_sha256(q3)

        self.assertEqual(h1, h2)
        self.assertEqual(h2, h3)

    def test_different_queries_produce_different_hashes(self):
        q1 = "query Q1 { me { id } }"
        q2 = "query Q2 { me { name } }"
        self.assertNotEqual(calculate_sha256(q1), calculate_sha256(q2))

    def test_empty_string_handling(self):
        self.assertEqual(calculate_sha256(""), "")
        self.assertEqual(calculate_sha256(None), "")


class TestAPQExtraction(unittest.TestCase):
    def setUp(self):
        self.extractor = APQOperationExtractor()

    def test_extract_apollo_apq_hash_from_code(self):
        code = """
        import { createPersistedQueryLink } from "@apollo/client/link/persisted-queries";

        const request = {
          operationName: "GetUserFeed",
          extensions: {
            persistedQuery: {
              version: 1,
              sha256Hash: "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
            }
          }
        };
        """
        records = self.extractor.extract_from_code(code)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.sha256_hash, "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38")
        self.assertEqual(r.operation_name, "GetUserFeed")
        self.assertEqual(r.source, "bundle_ast")

    def test_extract_url_encoded_apq(self):
        code = """
        const endpoint = "https://api.example.com/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22b86550244199c08a9010ab87483a9032128779958117dcf49decfbc612f0ec35%22%7D%7D";
        """
        records = self.extractor.extract_from_code(code)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].sha256_hash, "b86550244199c08a9010ab87483a9032128779958117dcf49decfbc612f0ec35")

    def test_extract_relay_persisted_queries(self):
        code = """
        // Relay doc_id call
        fetch('/graphql', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            doc_id: 'relay-doc-xyz12345678',
            operationName: 'RelayDashboardQuery',
            query: 'query RelayDashboardQuery { dashboard { stats } }'
          })
        });
        """
        records = self.extractor.extract_from_code(code)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.sha256_hash, "relay-doc-xyz12345678")
        self.assertEqual(r.operation_name, "RelayDashboardQuery")
        self.assertIsNotNone(r.query_string)

    def test_extract_bundle_manifest_dictionary(self):
        code = """
        // JS bundle dictionary mapping hash to query
        const queryManifest = {
          "3f5b8c9d1234567890abcdef1234567890abcdef1234567890abcdef12345678": "query GetCatalog { catalog { items { id name } } }",
          "7a8b9c0d1234567890abcdef1234567890abcdef1234567890abcdef12345678": "mutation AddItem($input: ItemInput!) { addItem(input: $input) { id } }"
        };
        """
        records = self.extractor.extract_from_code(code)
        self.assertEqual(len(records), 2)
        hashes = {r.sha256_hash for r in records}
        self.assertIn("3f5b8c9d1234567890abcdef1234567890abcdef1234567890abcdef12345678", hashes)
        self.assertIn("7a8b9c0d1234567890abcdef1234567890abcdef1234567890abcdef12345678", hashes)

    def test_extract_apollo_persisted_query_manifest_json(self):
        manifest_json = """
        {
          "format": "apollo-persisted-query-manifest",
          "version": 1,
          "operations": [
            {
              "id": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38",
              "name": "CurrentUserQuery",
              "body": "query CurrentUserQuery { me { id username email } }"
            },
            {
              "id": "b86550244199c08a9010ab87483a9032128779958117dcf49decfbc612f0ec35",
              "name": "UpdateEmailMutation",
              "body": "mutation UpdateEmailMutation($email: String!) { updateEmail(email: $email) { id } }"
            }
          ]
        }
        """
        records = self.extractor.extract_from_manifest(manifest_json)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].operation_name, "CurrentUserQuery")
        self.assertEqual(records[1].operation_name, "UpdateEmailMutation")
        self.assertEqual(records[0].source, "apq_manifest")

    def test_extract_from_har(self):
        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/graphql",
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "operationName": "GetSettings",
                                    "extensions": {
                                        "persistedQuery": {
                                            "version": 1,
                                            "sha256Hash": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
                                        }
                                    }
                                })
                            }
                        }
                    },
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000%22%7D%7D",
                            "queryString": [
                                {
                                    "name": "extensions",
                                    "value": json.dumps({
                                        "persistedQuery": {
                                            "version": 1,
                                            "sha256Hash": "aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000"
                                        }
                                    })
                                }
                            ]
                        }
                    }
                ]
            }
        }
        records = self.extractor.extract_from_har(har_data)
        self.assertEqual(len(records), 2)
        hashes = {r.sha256_hash for r in records}
        self.assertIn("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", hashes)
        self.assertIn("aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000", hashes)


class TestSDLSynthesis(unittest.TestCase):
    def test_synthesize_sdl_from_single_query(self):
        records = [
            PersistedQueryRecord(
                sha256_hash="1" * 64,
                operation_name="GetUserProfile",
                query_string="""
                query GetUserProfile($id: ID!, $limit: Int = 10) {
                  user(id: $id) {
                    id
                    name
                    email
                    posts(limit: $limit) {
                      id
                      title
                    }
                  }
                }
                """,
            )
        ]
        sdl = synthesize_sdl_from_records(records)
        self.assertIn("type Query", sdl)
        self.assertIn("user(id: ID!): User", sdl)
        self.assertIn("type User", sdl)
        self.assertIn("posts(limit: Int): [Post]", sdl)
        self.assertIn("type Post", sdl)

        # Validate with graphql-core build_schema
        schema = build_schema(sdl)
        self.assertIsNotNone(schema.query_type)
        self.assertIn("user", schema.query_type.fields)

    def test_synthesize_sdl_merging_queries_and_mutations(self):
        records = [
            PersistedQueryRecord(
                sha256_hash="1" * 64,
                query_string="""
                query GetUsers {
                  users {
                    id
                    name
                  }
                }
                """,
            ),
            PersistedQueryRecord(
                sha256_hash="2" * 64,
                query_string="""
                query GetUsersWithEmail {
                  users {
                    email
                    avatarUrl
                  }
                }
                """,
            ),
            PersistedQueryRecord(
                sha256_hash="3" * 64,
                query_string="""
                mutation CreateUser($input: CreateUserInput!) {
                  createUser(input: $input) {
                    id
                    name
                  }
                }
                """,
            ),
            PersistedQueryRecord(
                sha256_hash="4" * 64,
                query_string="""
                subscription OnUserAdded {
                  userAdded {
                    id
                  }
                }
                """,
            ),
        ]
        sdl = synthesize_sdl_from_records(records)

        # Ensure all operations are represented
        self.assertIn("type Query", sdl)
        self.assertIn("type Mutation", sdl)
        self.assertIn("type Subscription", sdl)
        self.assertIn("createUser(input: CreateUserInput!): User", sdl)
        self.assertIn("scalar CreateUserInput", sdl)

        # Validate with graphql-core
        schema = build_schema(sdl)
        self.assertIn("users", schema.query_type.fields)
        self.assertIn("createUser", schema.mutation_type.fields)
        self.assertIn("userAdded", schema.subscription_type.fields)

        # Check merged User fields
        user_type = schema.type_map["User"]
        self.assertIn("id", user_type.fields)
        self.assertIn("name", user_type.fields)
        self.assertIn("email", user_type.fields)
        self.assertIn("avatarUrl", user_type.fields)

    def test_synthesize_sdl_with_fragments(self):
        records = [
            PersistedQueryRecord(
                sha256_hash="5" * 64,
                query_string="""
                query GetArticle {
                  article {
                    ...ArticleDetails
                  }
                }
                fragment ArticleDetails on Article {
                  id
                  title
                  content
                  viewCount
                }
                """,
            )
        ]
        sdl = synthesize_sdl_from_records(records)
        self.assertIn("type Article", sdl)

        schema = build_schema(sdl)
        article_type = schema.type_map["Article"]
        self.assertIn("title", article_type.fields)
        self.assertIn("viewCount", article_type.fields)

    def test_synthesize_sdl_empty_records(self):
        self.assertEqual(synthesize_sdl_from_records([]), "")
        self.assertEqual(
            synthesize_sdl_from_records([PersistedQueryRecord(sha256_hash="a" * 64, query_string=None)]),
            "",
        )


class TestGraphQLProberAPQ(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.prober = GraphQLProber(timeout=5.0)

    async def test_probe_apq_hash_success(self):
        """Tests probe_apq_hash with active APQ response returning data."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                ext = body.get("extensions", {})
                pq = ext.get("persistedQuery", {})
                if pq.get("sha256Hash") == "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38":
                    return httpx.Response(200, json={"data": {"user": {"id": "1", "name": "Alice"}}})
            return httpx.Response(400)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_apq_hash(
                "http://testserver/graphql",
                sha256_hash="ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38",
                operation_name="GetUser",
                client=client,
            )

        self.assertTrue(result.is_active)
        self.assertTrue(result.supports_post)
        self.assertIn("GetUser", result.query_fields)
        self.assertIsNone(result.error)

    async def test_probe_apq_hash_persisted_query_not_found(self):
        """Tests probe_apq_hash verifying APQ support via PersistedQueryNotFound."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(
                    200,
                    json={
                        "errors": [
                            {
                                "message": "PersistedQueryNotFound",
                                "extensions": {"code": "PERSISTED_QUERY_NOT_FOUND"},
                            }
                        ]
                    },
                )
            return httpx.Response(400)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_apq_hash(
                "http://testserver/graphql",
                sha256_hash="not_in_cache_hash_1234567890abcdef1234567890abcdef1234567890abcdef",
                client=client,
            )

        self.assertTrue(result.is_active)
        self.assertTrue(result.supports_post)
        self.assertIsNone(result.error)

    async def test_probe_apq_hash_get_fallback(self):
        """Tests probe_apq_hash falling back to GET when POST fails with 405."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(405, text="Method Not Allowed")
            elif request.method == "GET":
                ext_str = request.url.params.get("extensions", "")
                if "sha256Hash" in ext_str:
                    return httpx.Response(200, json={"data": {"status": "ok"}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_apq_hash(
                "http://testserver/graphql",
                sha256_hash="b86550244199c08a9010ab87483a9032128779958117dcf49decfbc612f0ec35",
                operation_name="GetStatus",
                client=client,
            )

        self.assertTrue(result.is_active)
        self.assertFalse(result.supports_post)
        self.assertTrue(result.supports_get)
        self.assertIn("GetStatus", result.query_fields)
        self.assertIsNone(result.error)

    async def test_probe_apq_hash_inactive(self):
        """Tests probe_apq_hash rejecting non-GraphQL 404 endpoint."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_apq_hash(
                "http://testserver/not-graphql",
                sha256_hash="0000000000000000000000000000000000000000000000000000000000000000",
                client=client,
            )

        self.assertFalse(result.is_active)
        self.assertIsNotNone(result.error)


if __name__ == "__main__":
    unittest.main()
