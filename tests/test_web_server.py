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


if __name__ == "__main__":
    unittest.main()
