"""
Tests for api_tool.web runner and HTTP server.
"""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch
import httpx

from api_tool.models import DiscoveredEndpoint
from api_tool.web.runner import ScanRunner
from api_tool.web.server import WebAppServer


class TestScanRunner(unittest.IsolatedAsyncioTestCase):
    async def test_runner_initial_state(self):
        runner = ScanRunner()
        status = runner.get_status()
        self.assertEqual(status["status"], "idle")
        self.assertEqual(status["stage"], "idle")
        self.assertEqual(len(runner.logs), 0)

    async def test_runner_log_capture(self):
        runner = ScanRunner()
        runner.add_log("INFO", "Test info message", "test_logger")
        runner.add_log("ERROR", "Test error message", "test_logger")

        logs = runner.get_logs(0)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["level"], "INFO")
        self.assertEqual(logs[1]["level"], "ERROR")

        # Offset test
        logs_offset = runner.get_logs(1)
        self.assertEqual(len(logs_offset), 1)
        self.assertEqual(logs_offset[0]["level"], "ERROR")

    async def test_runner_mock_scan_execution(self):
        runner = ScanRunner()

        # Mock the pipeline methods to run fast without actual network calls
        with patch.object(runner, "_execute_pipeline", new_callable=AsyncMock) as mock_exec:
            async def fake_pipeline(opts):
                runner.endpoints.append(
                    DiscoveredEndpoint(path="/api/v1/users", method="GET", base_url="https://example.com")
                )
                runner.add_log("INFO", "Discovered /api/v1/users", "mock")

            mock_exec.side_effect = fake_pipeline
            await runner.run("https://example.com", {"crawl": False})

            self.assertEqual(runner.status, "completed")
            self.assertEqual(len(runner.endpoints), 1)
            results = runner.get_results()
            self.assertEqual(len(results["endpoints"]), 1)
            self.assertEqual(results["endpoints"][0]["path"], "/api/v1/users")

    async def test_runner_pipeline_with_chunk_cracking_and_mock_transport(self):
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/static/main.js"></script>
        </head>
        <body>
            <a href="/dashboard">Dashboard</a>
        </body>
        </html>
        """
        main_js = """
        fetch('/api/v1/profile');
        __webpack_require__.u = function(chunkId) {
            return "" + chunkId + "." + {"101": "hashA"}[chunkId] + ".js";
        };
        """
        chunk_js = """
        const target = `/api/v2/admin/${adminId}/settings`;
        fetch(target);
        """

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == "https://testapp.io/":
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html_content)
            elif url_str == "https://testapp.io/static/main.js":
                return httpx.Response(200, headers={"Content-Type": "application/javascript"}, text=main_js)
            elif "101.hashA.js" in url_str:
                return httpx.Response(200, headers={"Content-Type": "application/javascript"}, text=chunk_js)
            elif url_str == "https://testapp.io/dashboard":
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<h1>Dashboard</h1>")
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        runner = ScanRunner()

        opts = {
            "mock_transport": transport,
            "crawl": True,
            "max_depth": 1,
            "max_pages": 5,
            "manifest": False,
            "static_analysis": True,
            "probe": False,
            "passive_osint": False,
        }

        await runner.run("https://testapp.io", opts)

        self.assertEqual(runner.status, "completed")
        paths = {e.path for e in runner.endpoints}
        # Discovered from crawler: /dashboard
        self.assertTrue(any("/dashboard" in p for p in paths))
        # Discovered from main.js Pass 1: /api/v1/profile
        self.assertIn("/api/v1/profile", paths)
        # Discovered from cracked chunk 101 in Pass 2: /api/v2/admin/{adminId}/settings
        self.assertTrue(any("{adminId}" in p for p in paths))
        # Chunk manifests recorded
        self.assertGreaterEqual(len(runner.chunk_manifests), 1)


class TestWebServerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Bind to port 0 (dynamic port) on localhost
        cls.server = WebAppServer(host="127.0.0.1", port=0)
        cls.server.start(block=False)
        cls.base_url = f"http://127.0.0.1:{cls.server.actual_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_get_index_html(self):
        resp = httpx.get(f"{self.base_url}/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("MINIATURE ENGINE", resp.text)
        self.assertIn("FEEDBACK & LOGS", resp.text)
        self.assertIn("Copy All Logs", resp.text)

    def test_get_status_api(self):
        resp = httpx.get(f"{self.base_url}/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("counts", data)

    def test_get_logs_api(self):
        self.server.runner.add_log("INFO", "Log endpoint verification test", "test")
        resp = httpx.get(f"{self.base_url}/api/logs?offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("logs", data)
        self.assertGreater(len(data["logs"]), 0)

    def test_post_scan_validation(self):
        # Empty URL should return 400
        resp = httpx.post(f"{self.base_url}/api/scan", json={"url": ""})
        self.assertEqual(resp.status_code, 400)

    def test_post_import_har(self):
        har_payload = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/v1/auth/login",
                            "headers": [{"name": "Authorization", "value": "Bearer test-token"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"username": "admin"}'
                            }
                        },
                        "response": {
                            "status": 200,
                            "content": {
                                "mimeType": "application/json",
                                "text": '{"token": "xyz"}'
                            }
                        }
                    }
                ]
            }
        }
        resp = httpx.post(f"{self.base_url}/api/import/har", json=har_payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["endpoints_count"], 1)

        # Check results API
        results_resp = httpx.get(f"{self.base_url}/api/results")
        self.assertEqual(results_resp.status_code, 200)
        res_data = results_resp.json()
        self.assertEqual(len(res_data["endpoints"]), 1)
        self.assertEqual(res_data["endpoints"][0]["path"], "/v1/auth/login")

    def test_export_openapi(self):
        # JSON format
        resp = httpx.get(f"{self.base_url}/api/export/openapi?format=json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("openapi", resp.json())

        # YAML format
        resp_yaml = httpx.get(f"{self.base_url}/api/export/openapi?format=yaml")
        self.assertEqual(resp_yaml.status_code, 200)
        self.assertIn("openapi:", resp_yaml.text)

    def test_export_postman(self):
        resp = httpx.get(f"{self.base_url}/api/export/postman")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("info", data)
        self.assertIn("schema", data["info"])

    def test_export_graphql(self):
        resp = httpx.get(f"{self.base_url}/api/export/graphql")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("schema", resp.text)


if __name__ == "__main__":
    unittest.main()
