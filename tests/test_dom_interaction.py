"""
Isolated Unit Tests for Headless DOM Synthetic Interaction Subsystem.
Tests:
1. Synthetic interaction triggering dynamic fetch/XHR calls.
2. Modal/drawer opening with MutationObserver takeRecords() capturing newly mounted links and forms.
3. Input event simulation (input, change, keydown:Enter with test query).
4. window.history.pushState and replaceState client-side route transitions.
5. DOM skeleton hashing and redundant state deduplication.
6. interact flag and max_interactions budget control.
"""

import asyncio
import unittest
from api_tool.runtime import HappyDOMEngine


class TestDOMInteraction(unittest.TestCase):
    """Test suite for HappyDOMEngine synthetic interaction and mutation observation."""

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_interaction_triggers_dynamic_fetch(self):
        """Tests that synthetic click on button triggers dynamic fetch and records it."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Synthetic Interaction Test</title></head>
        <body>
            <button id="load-btn">Load Remote Data</button>
            <script>
                document.getElementById('load-btn').addEventListener('click', () => {
                    fetch('/api/v2/interactive-users?source=synthetic', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Custom-Trigger': 'synthetic-runner'
                        },
                        body: JSON.stringify({ action: 'load_users', page: 1 })
                    });
                });
            </script>
        </body>
        </html>
        """

        # 1. With interact=True (default)
        result_active = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com/app",
                html=test_html,
                interact=True,
            )
        )

        endpoints = result_active.get("dynamic_endpoints", [])
        urls = [ep.get("url") for ep in endpoints]
        self.assertIn("/api/v2/interactive-users?source=synthetic", urls)

        call = next(
            ep for ep in endpoints if ep.get("url") == "/api/v2/interactive-users?source=synthetic"
        )
        self.assertEqual(call.get("method"), "POST")
        self.assertEqual(call.get("type"), "fetch")
        self.assertEqual(
            call.get("headers", {}).get("X-Custom-Trigger"), "synthetic-runner"
        )
        self.assertIn("load_users", call.get("body", ""))

        # 2. With interact=False
        result_inactive = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com/app",
                html=test_html,
                interact=False,
            )
        )
        inactive_urls = [ep.get("url") for ep in result_inactive.get("dynamic_endpoints", [])]
        self.assertNotIn("/api/v2/interactive-users?source=synthetic", inactive_urls)

    def test_modal_opening_take_records_captures_links_and_forms(self):
        """Tests that modal opening triggers takeRecords() to extract newly mounted links and forms."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <button id="open-modal-btn">Open Dialog</button>
            <script>
                document.getElementById('open-modal-btn').addEventListener('click', () => {
                    const modal = document.createElement('div');
                    modal.setAttribute('role', 'dialog');
                    modal.className = 'modal-container';
                    modal.innerHTML = `
                        <h2>Security Settings</h2>
                        <a href="/admin/secret-settings">Secret Settings Link</a>
                        <span data-url="/api/internal/telemetry">Telemetry Endpoint</span>
                        <form action="/auth/verify-mfa" method="POST">
                            <input name="otp_code" type="text" value="123456" />
                            <input name="csrf_token" type="hidden" value="xyz987" />
                            <button type="submit">Verify MFA</button>
                        </form>
                    `;
                    document.body.appendChild(modal);
                });
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
                interact=True,
            )
        )

        mutation_links = result.get("mutation_links", [])
        discovered_links = result.get("discovered_links", [])
        forms = result.get("forms", [])

        # Verify mutation links captured by takeRecords()
        self.assertIn("/admin/secret-settings", mutation_links)
        self.assertIn("/api/internal/telemetry", mutation_links)
        self.assertIn("/auth/verify-mfa", mutation_links)

        # Verify links also present in discovered_links
        self.assertIn("/admin/secret-settings", discovered_links)
        self.assertIn("/api/internal/telemetry", discovered_links)

        # Verify modal form extraction
        mfa_form = next((f for f in forms if f.get("action") == "/auth/verify-mfa"), None)
        self.assertIsNotNone(mfa_form)
        self.assertEqual(mfa_form.get("method"), "POST")
        input_names = [inp.get("name") for inp in mfa_form.get("inputs", [])]
        self.assertIn("otp_code", input_names)
        self.assertIn("csrf_token", input_names)

    def test_input_event_simulation(self):
        """Tests dispatching input, change, and keydown:Enter events with test query."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <input type="search" id="search-box" placeholder="Search API..." />
            <input type="text" id="filter-box" placeholder="Filter..." />
            <script>
                const searchBox = document.getElementById('search-box');
                searchBox.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        fetch('/api/v1/search?q=' + encodeURIComponent(searchBox.value));
                    }
                });

                const filterBox = document.getElementById('filter-box');
                filterBox.addEventListener('change', () => {
                    fetch('/api/v1/filter?name=' + encodeURIComponent(filterBox.value));
                });
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
                interact=True,
            )
        )

        endpoints = result.get("dynamic_endpoints", [])
        urls = [ep.get("url") for ep in endpoints]

        # Verified that test query 'test' was populated and keydown:Enter triggered search fetch
        self.assertIn("/api/v1/search?q=test", urls)
        # Verified that change event triggered filter fetch
        self.assertIn("/api/v1/filter?name=test", urls)

    def test_pushstate_route_capture(self):
        """Tests intercepting window.history.pushState and replaceState client-side routes."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <button id="push-btn">Go To Settings</button>
            <button id="replace-btn">Update Location</button>
            <script>
                document.getElementById('push-btn').addEventListener('click', () => {
                    window.history.pushState({ page: 'settings' }, 'Settings', '/app/account/security');
                });
                document.getElementById('replace-btn').addEventListener('click', () => {
                    window.history.replaceState({ page: 'overview' }, 'Overview', '/app/dashboard/overview');
                });
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com/app",
                html=test_html,
                interact=True,
            )
        )

        pushed_routes = result.get("pushed_routes", [])
        self.assertIn("/app/account/security", pushed_routes)
        self.assertIn("/app/dashboard/overview", pushed_routes)

        discovered_links = result.get("discovered_links", [])
        self.assertIn("/app/account/security", discovered_links)
        self.assertIn("/app/dashboard/overview", discovered_links)

    def test_attribute_mutation_link_extraction(self):
        """Tests MutationObserver attribute mutation extraction (href, data-url, action)."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <button id="update-btn">Mutate Attributes</button>
            <a id="link-target" href="/original-url">Initial Target</a>
            <script>
                document.getElementById('update-btn').addEventListener('click', () => {
                    const link = document.getElementById('link-target');
                    link.setAttribute('href', '/mutated-destination-link');
                    link.setAttribute('data-url', '/mutated-api-data');
                });
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
                interact=True,
            )
        )

        mutation_links = result.get("mutation_links", [])
        self.assertIn("/mutated-destination-link", mutation_links)
        self.assertIn("/mutated-api-data", mutation_links)

    def test_dom_skeleton_hash_deduplication(self):
        """Tests that structural DOM skeleton hashing deduplicates identical states and terminates cleanly."""
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <button id="btn1">Add Notice A</button>
            <button id="btn2">Add Notice B</button>
            <button id="btn3">Add Notice C</button>
            <div id="container"></div>
            <script>
                function addAlert() {
                    const div = document.createElement('div');
                    div.className = 'alert-box';
                    div.innerHTML = '<span>Alert Message</span>';
                    document.getElementById('container').appendChild(div);
                }
                document.getElementById('btn1').addEventListener('click', addAlert);
                document.getElementById('btn2').addEventListener('click', addAlert);
                document.getElementById('btn3').addEventListener('click', addAlert);
            </script>
        </body>
        </html>
        """

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
                interact=True,
                max_interactions=10,
            )
        )

        self.assertIsInstance(result, dict)
        self.assertIn("rendered_html", result)
        self.assertIn("Alert Message", result["rendered_html"])

    def test_max_interactions_boundary_enforcement(self):
        """Tests that max_interactions strictly caps synthetic interactions."""
        # 10 buttons that each call an endpoint
        buttons_html = "".join(
            f'<button id="btn-{i}">Action {i}</button>' for i in range(10)
        )
        script_html = """
        <script>
            for (let i = 0; i < 10; i++) {
                const btn = document.getElementById('btn-' + i);
                if (btn) {
                    btn.addEventListener('click', () => {
                        fetch('/api/action/' + i);
                    });
                }
            }
        </script>
        """
        test_html = f"<!DOCTYPE html><html><body>{buttons_html}{script_html}</body></html>"

        result = self.loop.run_until_complete(
            HappyDOMEngine.evaluate(
                url="https://example.com",
                html=test_html,
                interact=True,
                max_interactions=3,
            )
        )

        endpoints = result.get("dynamic_endpoints", [])
        # Exactly 3 interactions should have executed
        self.assertEqual(len(endpoints), 3)


if __name__ == "__main__":
    unittest.main()
