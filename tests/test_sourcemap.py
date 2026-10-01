"""
Unit and integration tests for api_tool.analyzer.sourcemap:
- sanitize_source_path (Zip Slip / path traversal defense)
- extract_from_json (Standard V3 and Index Map sections)
- extract_from_js (sourceMappingURL comments and inline Data URIs)
- probe_map_urls (hidden-source-map URL generation)
- fetch_and_unpack (Async end-to-end extraction)
- save_to_disk (Safe disk persistence with canonical path validation)
"""

import asyncio
import base64
import json
import os
import shutil
import tempfile
import unittest
import httpx

from api_tool.models import DiscoveredEndpoint, SourceMapFile, SourceMapResult
from api_tool.analyzer.sourcemap import (
    SourceMapUnpacker,
    sanitize_source_path,
)


class TestPathSanitization(unittest.TestCase):
    def test_directory_traversal_stripping(self):
        # Path traversal sequences should be neutralized and stripped
        self.assertEqual(sanitize_source_path("../../../etc/passwd"), "etc/passwd")
        self.assertEqual(sanitize_source_path("....//....//etc/shadow"), "etc/shadow")
        self.assertEqual(sanitize_source_path("..\\..\\..\\windows\\system32\\cmd.exe"), "windows/system32/cmd.exe")
        self.assertEqual(sanitize_source_path("/usr/local/bin/malicious"), "usr/local/bin/malicious")
        self.assertEqual(sanitize_source_path(".."), "")
        self.assertEqual(sanitize_source_path("../.."), "")
        self.assertEqual(sanitize_source_path("././."), "")

    def test_null_bytes_and_control_chars(self):
        # Null bytes and ASCII control characters must be purged
        self.assertEqual(sanitize_source_path("\x00/etc/passwd"), "etc/passwd")
        self.assertEqual(sanitize_source_path("src/\x01\x02auth.ts"), "src/auth.ts")

    def test_url_encoded_traversals(self):
        # %2e%2e%2f is ../
        self.assertEqual(sanitize_source_path("%2e%2e%2f%2e%2e%2fsecret.key"), "secret.key")
        # Double URL encoding
        self.assertEqual(sanitize_source_path("%252e%252e%252fprivate.pem"), "private.pem")

    def test_bundler_virtual_prefixes(self):
        # Webpack
        self.assertEqual(sanitize_source_path("webpack:///./src/index.ts"), "src/index.ts")
        self.assertEqual(sanitize_source_path("webpack-internal:///src/api/auth.js"), "src/api/auth.js")
        self.assertEqual(sanitize_source_path("webpack://_N_E/src/components/Header.tsx"), "src/components/Header.tsx")
        
        # Turbopack
        self.assertEqual(sanitize_source_path("turbopack:///[project]/src/utils/http.ts"), "src/utils/http.ts")
        
        # Vite, Angular, Rollup
        self.assertEqual(sanitize_source_path("vite://src/main.ts"), "src/main.ts")
        self.assertEqual(sanitize_source_path("ng:///AppModule/app.component.ts"), "AppModule/app.component.ts")
        self.assertEqual(sanitize_source_path("rollup:///src/lib/calc.js"), "src/lib/calc.js")
        self.assertEqual(sanitize_source_path("file:///home/user/project/index.js"), "home/user/project/index.js")

    def test_windows_reserved_names_and_drive_letters(self):
        # Reserved names must be neutralized
        self.assertEqual(sanitize_source_path("CON.txt"), "_CON.txt")
        self.assertEqual(sanitize_source_path("aux.json"), "_aux.json")
        self.assertEqual(sanitize_source_path("nul"), "_nul")
        self.assertEqual(sanitize_source_path("src/com1.js"), "src/_com1.js")
        
        # Drive letters
        self.assertEqual(sanitize_source_path("C:\\Windows\\System32\\calc.exe"), "Windows/System32/calc.exe")
        self.assertEqual(sanitize_source_path("D:/Projects/app/src/index.ts"), "Projects/app/src/index.ts")

    def test_query_and_hash_stripping(self):
        # Vite / Vue loaders attach query strings
        self.assertEqual(sanitize_source_path("src/App.vue?vue&type=script&lang.ts"), "src/App.vue")
        self.assertEqual(sanitize_source_path("src/styles.css?module#main"), "src/styles.css")


class TestSourceMapUnpackerJson(unittest.TestCase):
    def setUp(self):
        self.unpacker = SourceMapUnpacker()

    def test_extract_standard_v3(self):
        map_data = {
            "version": 3,
            "file": "app.bundle.js",
            "sources": [
                "webpack:///src/api/auth.ts",
                "turbopack:///[project]/src/utils/http.ts",
                "webpack:///node_modules/axios/index.js",
            ],
            "sourcesContent": [
                "export const login = (u, p) => fetch('/api/login');",
                "export const API_URL = 'https://api.example.com';",
                "module.exports = {};",
            ],
            "mappings": "AAAA;...",
        }
        result = self.unpacker.extract_from_json(map_data, base_source_url="https://example.com/app.bundle.js.map")

        self.assertEqual(len(result.files), 3)
        self.assertEqual(result.sources, ["src/api/auth.ts", "src/utils/http.ts", "node_modules/axios/index.js"])

        auth_file = result.get_file("src/api/auth.ts")
        self.assertIsNotNone(auth_file)
        self.assertEqual(auth_file.extension, ".ts")
        self.assertFalse(auth_file.is_node_modules)
        self.assertIn("fetch('/api/login')", auth_file.content)

        axios_file = result.get_file("node_modules/axios/index.js")
        self.assertIsNotNone(axios_file)
        self.assertTrue(axios_file.is_node_modules)

        # First party application files
        app_files = result.get_application_files()
        self.assertEqual(len(app_files), 2)

    def test_extract_index_map_sections(self):
        # Index Map with embedded map section and external url section
        index_map = {
            "version": 3,
            "file": "main.js",
            "sections": [
                {
                    "offset": {"line": 0, "column": 0},
                    "map": {
                        "version": 3,
                        "sources": ["turbopack:///[project]/src/dashboard.tsx"],
                        "sourcesContent": ["export const Dashboard = () => <div>Hello</div>;"],
                    },
                },
                {
                    "offset": {"line": 1000, "column": 0},
                    "url": "chunks/chunk2.js.map",
                },
            ],
        }
        result = self.unpacker.extract_from_json(
            index_map,
            base_source_url="https://example.com/static/main.js.map",
        )

        self.assertEqual(len(result.files), 1)
        self.assertIn("src/dashboard.tsx", result.sources)
        self.assertIn("https://example.com/static/chunks/chunk2.js.map", result.unresolved_sections)

    def test_route_and_endpoint_discovery(self):
        # Next.js App Router and Pages Router files
        map_data = {
            "version": 3,
            "file": "app.js",
            "sources": [
                "webpack:///src/app/api/users/route.ts",
                "webpack:///src/app/(dashboard)/api/orders/[id]/route.ts",
                "webpack:///pages/api/auth/[...nextauth].ts",
            ],
            "sourcesContent": [
                """
                export async function GET(req: Request) { return Response.json([]); }
                export async function POST(req: Request) { return Response.json({}); }
                """,
                """
                export async function DELETE(req: Request) { return Response.json({}); }
                """,
                """
                export default function handler(req, res) { res.status(200).send(); }
                """,
            ],
        }
        result = self.unpacker.extract_from_json(map_data, base_source_url="https://example.com/app.js.map")

        self.assertEqual(len(result.endpoints), 4)
        endpoints_by_path = {(e.path, e.method) for e in result.endpoints}

        self.assertIn(("/api/users", "GET"), endpoints_by_path)
        self.assertIn(("/api/users", "POST"), endpoints_by_path)
        self.assertIn(("/api/orders/{id}", "DELETE"), endpoints_by_path)
        self.assertIn(("/api/auth/{nextauth*}", "GET"), endpoints_by_path)

    def test_memory_safe_mappings_stripping(self):
        # Create synthetic 12MB mappings string
        huge_mappings = "AAAA;;;qEAAA,IAAI;" * 700000
        json_data = json.dumps({
            "version": 3,
            "file": "huge.js",
            "sources": ["src/huge_app.ts"],
            "mappings": huge_mappings,
            "sourcesContent": ["console.log('memory safe');"],
        })
        self.assertGreater(len(json_data), 10 * 1024 * 1024)  # > 10MB

        # Unpack should execute without memory explosion
        result = self.unpacker.extract_from_json(json_data)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].path, "src/huge_app.ts")
        self.assertEqual(result.files[0].content, "console.log('memory safe');")


class TestSourceMapUnpackerJs(unittest.TestCase):
    def setUp(self):
        self.unpacker = SourceMapUnpacker()

    def test_extract_comment_url(self):
        js = """
        function hello() { console.log('world'); }
        //# sourceMappingURL=app.bundle.js.map
        """
        ref = self.unpacker.extract_from_js(js, base_url="https://example.com/assets/app.js")
        self.assertIsNotNone(ref)
        self.assertFalse(ref.is_inline)
        self.assertEqual(ref.url, "https://example.com/assets/app.bundle.js.map")
        self.assertEqual(str(ref), "https://example.com/assets/app.bundle.js.map")

    def test_extract_block_comment_url(self):
        js = """
        function hello() { console.log('world'); }
        /*# sourceMappingURL=app.bundle.js.map */
        """
        ref = self.unpacker.extract_from_js(js, base_url="https://example.com/assets/app.js")
        self.assertIsNotNone(ref)
        self.assertEqual(ref.url, "https://example.com/assets/app.bundle.js.map")

    def test_extract_inline_base64_data_uri(self):
        embedded_map = {
            "version": 3,
            "sources": ["inline_test.ts"],
            "sourcesContent": ["const test = true;"],
        }
        b64 = base64.b64encode(json.dumps(embedded_map).encode("utf-8")).decode("utf-8")
        js = f"console.log('inline');\n//# sourceMappingURL=data:application/json;base64,{b64}"

        ref = self.unpacker.extract_from_js(js)
        self.assertIsNotNone(ref)
        self.assertTrue(ref.is_inline)
        self.assertIsNotNone(ref.inline_json)
        self.assertIn("inline_test.ts", ref.inline_json)

    def test_probe_map_urls(self):
        next_chunk = "https://example.com/_next/static/chunks/app/dashboard-c0ffee1234abcd.js?v=2"
        candidates = self.unpacker.probe_map_urls(next_chunk)

        # Verify key candidate URLs are generated
        self.assertIn("https://example.com/_next/static/chunks/app/dashboard-c0ffee1234abcd.js.map", candidates)
        self.assertIn("https://example.com/_next/static/chunks/app/dashboard-c0ffee1234abcd.map", candidates)
        self.assertIn("https://example.com/_next/static/chunks/app/dashboard.js.map", candidates)
        self.assertIn("https://example.com/_next/static/chunks/app/dashboard.map", candidates)
        self.assertIn("https://example.com/_next/static/chunks/app/maps/dashboard-c0ffee1234abcd.js.map", candidates)


class TestSafeDiskPersistence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.unpacker = SourceMapUnpacker()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_to_disk_safe(self):
        map_data = {
            "version": 3,
            "sources": ["src/api/auth.ts", "src/components/Button.tsx"],
            "sourcesContent": [
                "export const auth = true;",
                "export const Button = () => null;",
            ],
        }
        result = self.unpacker.extract_from_json(map_data)
        written = result.save_to_disk(self.temp_dir)

        self.assertEqual(len(written), 2)
        auth_file = os.path.join(self.temp_dir, "src/api/auth.ts")
        self.assertTrue(os.path.exists(auth_file))
        with open(auth_file, "r") as f:
            self.assertEqual(f.read(), "export const auth = true;")

    def test_save_to_disk_blocks_zip_slip_attempt(self):
        # Even if a malicious file entry slips into SourceMapFile, save_to_disk must reject it
        malicious_file = SourceMapFile(
            path="../../etc/evil.txt",
            original_path="../../etc/evil.txt",
            content="malicious payload",
        )
        result = SourceMapResult(files=[malicious_file])

        with self.assertRaises(ValueError):
            result.save_to_disk(self.temp_dir)


class TestFetchAndUnpackMocked(unittest.TestCase):
    def setUp(self):
        self.unpacker = SourceMapUnpacker()

    def test_fetch_and_unpack_inline(self):
        embedded_map = {
            "version": 3,
            "sources": ["src/config.ts"],
            "sourcesContent": ["export const CONFIG = { api: '/v1' };"],
        }
        b64 = base64.b64encode(json.dumps(embedded_map).encode("utf-8")).decode("utf-8")
        js_code = f"console.log('ok');\n//# sourceMappingURL=data:application/json;base64,{b64}"

        result = asyncio.run(
            self.unpacker.fetch_and_unpack("https://example.com/app.js", js_content=js_code)
        )

        self.assertEqual(result.discovery_source, "inline")
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].path, "src/config.ts")
        self.assertEqual(result.files[0].content, "export const CONFIG = { api: '/v1' };")

    def test_fetch_and_unpack_with_mock_client(self):
        # Mock httpx transport for comment URL resolution
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url == httpx.URL("https://example.com/app.js"):
                return httpx.Response(
                    200,
                    text="console.log('main');\n//# sourceMappingURL=app.js.map",
                )
            elif request.url == httpx.URL("https://example.com/app.js.map"):
                map_json = json.dumps({
                    "version": 3,
                    "sources": ["src/service.ts"],
                    "sourcesContent": ["export function doWork() {}"],
                })
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    text=map_json,
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_test():
            async with client:
                return await self.unpacker.fetch_and_unpack("https://example.com/app.js", client=client)

        result = asyncio.run(run_test())
        self.assertEqual(result.discovery_source, "comment")
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].path, "src/service.ts")

    def test_fetch_and_unpack_probe_hidden_source_map(self):
        # Mock httpx transport where JS has NO comment, but bundle.js.map exists
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url == httpx.URL("https://example.com/bundle.js"):
                return httpx.Response(200, text="console.log('minified bundle without comment');")
            elif request.url == httpx.URL("https://example.com/bundle.js.map"):
                map_json = json.dumps({
                    "version": 3,
                    "sources": ["src/hidden_secret.ts"],
                    "sourcesContent": ["export const SECRET = 'xyz123';"],
                })
                return httpx.Response(200, headers={"Content-Type": "application/json"}, text=map_json)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_test():
            async with client:
                return await self.unpacker.fetch_and_unpack("https://example.com/bundle.js", client=client)

        result = asyncio.run(run_test())
        self.assertEqual(result.discovery_source, "probe")
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].path, "src/hidden_secret.ts")


if __name__ == "__main__":
    unittest.main()
