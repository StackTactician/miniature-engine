"""
Isolated Unit Tests for HappyDOMEngine Headless DOM Subsystem.
Tests client-side JavaScript execution, dynamic API interception (fetch & XHR),
DOM link discovery, Shadow DOM traversal, and error/timeout handling.
"""

import asyncio
import unittest
from api_tool.runtime import HappyDOMEngine


class TestHappyDOMEngine(unittest.TestCase):
    """Test suite for HappyDOMEngine sidecar execution."""

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_is_available(self):
        """Verifies that Node.js runtime and runner script are available."""
        self.assertTrue(HappyDOMEngine.is_available())

    def test_evaluate_fetch_call(self):
        """Tests that inline JavaScript calling fetch('/api/v1/test') is intercepted."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test App</title></head>
        <body>
            <h1>Application Dashboard</h1>
            <a href="/dashboard">Dashboard Link</a>
            <script>
                fetch('/api/v1/test');
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com/app",
                html=test_html,
            )
        )

        self.assertIsInstance(result, dict)
        self.assertIn("rendered_html", result)
        self.assertIn("dynamic_endpoints", result)
        self.assertIn("discovered_links", result)

        endpoints = result["dynamic_endpoints"]
        self.assertIsInstance(endpoints, list)
        self.assertGreaterEqual(len(endpoints), 1)

        urls = [ep.get("url") for ep in endpoints if isinstance(ep, dict)]
        self.assertIn("/api/v1/test", urls)

        test_ep = next((ep for ep in endpoints if ep.get("url") == "/api/v1/test"), None)
        self.assertIsNotNone(test_ep)
        self.assertEqual(test_ep.get("method"), "GET")
        self.assertEqual(test_ep.get("type"), "fetch")

        # Verify discovered links
        self.assertIn("/dashboard", result["discovered_links"])
        # Verify rendered HTML contains page elements
        self.assertIn("Application Dashboard", result["rendered_html"])

    def test_evaluate_fetch_post_with_body_and_headers(self):
        """Tests interception of fetch with method POST, headers, and body."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script>
                fetch('/api/v1/submit', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': 'secret-token-123'
                    },
                    body: JSON.stringify({ action: 'create', value: 42 })
                });
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
            )
        )

        endpoints = result.get("dynamic_endpoints", [])
        post_ep = next((ep for ep in endpoints if ep.get("url") == "/api/v1/submit"), None)
        self.assertIsNotNone(post_ep)
        self.assertEqual(post_ep.get("method"), "POST")
        self.assertEqual(post_ep.get("type"), "fetch")
        self.assertIn("action", post_ep.get("body", ""))
        self.assertEqual(post_ep.get("headers", {}).get("X-API-Key"), "secret-token-123")

    def test_evaluate_xhr_call(self):
        """Tests that XMLHttpRequest calls are intercepted and recorded."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script>
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/v1/legacy-data');
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                xhr.send('sample-payload');
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
            )
        )

        endpoints = result.get("dynamic_endpoints", [])
        xhr_ep = next((ep for ep in endpoints if ep.get("url") == "/api/v1/legacy-data"), None)
        self.assertIsNotNone(xhr_ep)
        self.assertEqual(xhr_ep.get("method"), "POST")
        self.assertEqual(xhr_ep.get("type"), "xhr")
        self.assertEqual(xhr_ep.get("body"), "sample-payload")
        self.assertEqual(
            xhr_ep.get("headers", {}).get("X-Requested-With"), "XMLHttpRequest"
        )

    def test_evaluate_custom_elements_and_shadow_dom(self):
        """Tests custom elements and shadow DOM traversal for links and dynamic calls."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <nav-bar></nav-bar>
            <script>
                class NavBar extends HTMLElement {
                    connectedCallback() {
                        const shadow = this.attachShadow({ mode: 'open' });
                        shadow.innerHTML = '<a href="/shadow-settings">Shadow Settings</a>';
                        fetch('/api/v1/shadow-init');
                    }
                }
                customElements.define('nav-bar', NavBar);
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
            )
        )

        # Shadow link discovery
        self.assertIn("/shadow-settings", result.get("discovered_links", []))
        # Custom elements extraction
        self.assertIn("nav-bar", result.get("custom_elements", []))
        # Shadow fetch dynamic call
        urls = [ep.get("url") for ep in result.get("dynamic_endpoints", [])]
        self.assertIn("/api/v1/shadow-init", urls)

    def test_evaluate_forms_extraction(self):
        """Tests that forms and their input parameters are extracted."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/api/v1/auth/login" method="POST">
                <input name="username" type="text" value="alice" />
                <input name="password" type="password" value="" />
                <button type="submit">Log In</button>
            </form>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
            )
        )

        forms = result.get("forms", [])
        self.assertEqual(len(forms), 1)
        form = forms[0]
        self.assertEqual(form.get("action"), "/api/v1/auth/login")
        self.assertEqual(form.get("method"), "POST")
        input_names = [inp.get("name") for inp in form.get("inputs", [])]
        self.assertIn("username", input_names)
        self.assertIn("password", input_names)

    def test_evaluate_external_scripts(self):
        """Tests evaluation of external script strings passed to evaluate()."""
        test_html = "<!DOCTYPE html><html><body><h1>External Script Test</h1></body></html>"
        extra_scripts = [
            "fetch('/api/v1/from-external-script-1');",
            "fetch('/api/v1/from-external-script-2', { method: 'DELETE' });",
        ]

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
                scripts=extra_scripts,
            )
        )

        endpoints = result.get("dynamic_endpoints", [])
        urls = {ep.get("url"): ep.get("method") for ep in endpoints}
        self.assertIn("/api/v1/from-external-script-1", urls)
        self.assertEqual(urls["/api/v1/from-external-script-1"], "GET")
        self.assertIn("/api/v1/from-external-script-2", urls)
        self.assertEqual(urls["/api/v1/from-external-script-2"], "DELETE")

    def test_evaluate_empty_html(self):
        """Tests that empty HTML returns valid response structure without crashing."""
        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html="",
            )
        )
        self.assertIsInstance(result, dict)
        self.assertIn("rendered_html", result)
        self.assertEqual(result.get("dynamic_endpoints"), [])
        self.assertEqual(result.get("discovered_links"), [])

    def test_timeout_handling(self):
        """Tests that a strict timeout raises TimeoutError."""
        with self.assertRaises(TimeoutError):
            self.loop.run_until_complete(
                HappyDOMEngine.evaluate(
                    url="https://example.com",
                    html="<html><body><script>while(true){}</script></body></html>",
                    timeout=0.2,
                )
            )


if __name__ == "__main__":
    unittest.main()
