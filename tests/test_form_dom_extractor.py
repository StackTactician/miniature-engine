"""
Isolated unit tests for DOMExtractor, HTMXEndpoint, FormExtractor, and FormPayloadGenerator.
Tests deep DOM link, asset, frame, script, HTMX verb extraction,
and form parsing with method overrides, HTML5 button overrides, and realistic dummy fills.
"""

from __future__ import annotations

import unittest
from bs4 import BeautifulSoup

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter
from api_tool.spider.extractors import (
    DOMExtractor,
    FormControl,
    FormExtractor,
    FormPayloadGenerator,
    HTMXEndpoint,
)


class TestDOMExtractor(unittest.TestCase):
    """Test suite for DOMExtractor."""

    PAGE_URL = "https://example.com/app/index.html"

    def test_base_href_absolute(self):
        """Tests that relative links and assets resolve against an absolute <base href>."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <base href="https://assets.cdn.example.com/build/">
            <link rel="stylesheet" href="style.css">
            <script src="bundle.js"></script>
        </head>
        <body>
            <a href="dashboard">Dashboard</a>
            <img src="logo.png">
        </body>
        </html>
        """
        nav_links, script_urls, asset_urls, htmx_endpoints = DOMExtractor.extract(
            html, self.PAGE_URL
        )

        self.assertIn("https://assets.cdn.example.com/build/dashboard", nav_links)
        self.assertIn("https://assets.cdn.example.com/build/bundle.js", script_urls)
        self.assertIn("https://assets.cdn.example.com/build/style.css", asset_urls)
        self.assertIn("https://assets.cdn.example.com/build/logo.png", asset_urls)

    def test_base_href_relative(self):
        """Tests that relative <base href> resolves against page_url."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <base href="/v2/">
        </head>
        <body>
            <a href="login">Login</a>
        </body>
        </html>
        """
        nav_links, _, _, _ = DOMExtractor.extract(html, self.PAGE_URL)
        self.assertIn("https://example.com/v2/login", nav_links)

    def test_htmx_verbs(self):
        """Tests extraction of hx-get, hx-post, hx-put, hx-delete, hx-patch, and HTML5 data-hx-*."""
        html = """
        <div id="htmx-container">
            <button hx-get="/api/items">Get</button>
            <form hx-post="/api/items">Post</form>
            <button hx-put="/api/items/42">Put</button>
            <button hx-delete="/api/items/42">Delete</button>
            <button hx-patch="/api/items/42">Patch</button>
            <div data-hx-post="/api/items/html5">HTML5 Post</div>
        </div>
        """
        nav_links, script_urls, asset_urls, htmx_endpoints = DOMExtractor.extract(
            html, self.PAGE_URL
        )

        expected_pairs = [
            ("https://example.com/api/items", "GET"),
            ("https://example.com/api/items", "POST"),
            ("https://example.com/api/items/42", "PUT"),
            ("https://example.com/api/items/42", "DELETE"),
            ("https://example.com/api/items/42", "PATCH"),
            ("https://example.com/api/items/html5", "POST"),
        ]

        self.assertEqual(len(htmx_endpoints), len(expected_pairs))

        for url, method in expected_pairs:
            # Check flexible equality in either tuple order: (url, method) or (method, url)
            self.assertIn((url, method), htmx_endpoints)
            self.assertIn((method, url), htmx_endpoints)

        # Check HTMXEndpoint property access
        ep = htmx_endpoints[0]
        self.assertEqual(ep.url, "https://example.com/api/items")
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.verb, "GET")
        self.assertEqual(ep.path, "https://example.com/api/items")

    def test_data_url_attributes(self):
        """Tests data-url, data-href, data-target, data-endpoint, data-api, data-action, data-src."""
        html = """
        <div>
            <div data-url="/api/v1/profile">Profile</div>
            <a data-href="/settings">Settings</a>
            <button data-endpoint="/api/v2/analytics">Analytics</button>
            <span data-api="/api/v2/users">Users</span>
            <div data-action="/api/do-thing">Action</div>
            <button data-target="/modal-details">Target URL</button>
            <button data-target="#ignore-css-modal">CSS Target</button>
            <img data-src="/images/banner.jpg">
            <script data-src="/js/lazy.js"></script>
        </div>
        """
        nav_links, script_urls, asset_urls, _ = DOMExtractor.extract(
            html, self.PAGE_URL
        )

        self.assertIn("https://example.com/api/v1/profile", nav_links)
        self.assertIn("https://example.com/settings", nav_links)
        self.assertIn("https://example.com/api/v2/analytics", nav_links)
        self.assertIn("https://example.com/api/v2/users", nav_links)
        self.assertIn("https://example.com/api/do-thing", nav_links)
        self.assertIn("https://example.com/modal-details", nav_links)
        # CSS selector should NOT be extracted
        self.assertNotIn("https://example.com/#ignore-css-modal", nav_links)
        self.assertNotIn("#ignore-css-modal", nav_links)

        self.assertIn("https://example.com/images/banner.jpg", asset_urls)
        self.assertIn("https://example.com/js/lazy.js", script_urls)

    def test_html_comments(self):
        """Tests that URLs and candidate endpoints inside HTML comments are harvested."""
        html = """
        <!-- Reference API endpoint: /api/v2/internal/metrics -->
        <!-- Documentation: https://api.partner.io/v1/auth -->
        <!-- Bundled script: /static/legacy.js -->
        <!-- Banner asset: /static/hero.png -->
        <!-- Just a random non-URL comment -->
        """
        nav_links, script_urls, asset_urls, _ = DOMExtractor.extract(
            html, self.PAGE_URL
        )

        self.assertIn("https://example.com/api/v2/internal/metrics", nav_links)
        self.assertIn("https://api.partner.io/v1/auth", nav_links)
        self.assertIn("https://example.com/static/legacy.js", script_urls)
        self.assertIn("https://example.com/static/hero.png", asset_urls)

    def test_frames_and_multimedia(self):
        """Tests <iframe>, <frame>, <embed>, <object>, <video>, <audio>, <source>, <track>."""
        html = """
        <iframe src="/embed/chart.html"></iframe>
        <frameset>
            <frame src="/frame/sidebar.html">
        </frameset>
        <embed src="/media/movie.swf">
        <object data="/docs/report.pdf"></object>
        <video src="/media/intro.mp4" poster="/media/poster.jpg">
            <source src="/media/intro.webm" type="video/webm">
            <track src="/captions/en.vtt">
        </video>
        <audio src="/media/sound.mp3"></audio>
        <picture>
            <source srcset="/media/pic-2x.png 2x, /media/pic-1x.png 1x">
            <img src="/media/fallback.jpg" srcset="/media/hi.png 2x">
        </picture>
        """
        _, _, asset_urls, _ = DOMExtractor.extract(html, self.PAGE_URL)

        expected = [
            "https://example.com/embed/chart.html",
            "https://example.com/frame/sidebar.html",
            "https://example.com/media/movie.swf",
            "https://example.com/docs/report.pdf",
            "https://example.com/media/intro.mp4",
            "https://example.com/media/poster.jpg",
            "https://example.com/media/intro.webm",
            "https://example.com/captions/en.vtt",
            "https://example.com/media/sound.mp3",
            "https://example.com/media/pic-2x.png",
            "https://example.com/media/pic-1x.png",
            "https://example.com/media/fallback.jpg",
            "https://example.com/media/hi.png",
        ]
        for url in expected:
            self.assertIn(url, asset_urls)

    def test_inline_event_handlers(self):
        """Tests location.href, location.assign, window.open, location.replace in inline event handlers."""
        html = """
        <div>
            <button onclick="location.href='/user/dashboard'">Dashboard</button>
            <form onsubmit="location.assign('/checkout/success')">Form</form>
            <div onmouseover="window.open('/promo/popup', '_blank')">Promo</div>
            <a onclick="location.replace('/redirect/login')">Redirect</a>
            <span onclick="window.location='/quick-link'">Quick</span>
        </div>
        """
        nav_links, _, _, _ = DOMExtractor.extract(html, self.PAGE_URL)

        self.assertIn("https://example.com/user/dashboard", nav_links)
        self.assertIn("https://example.com/checkout/success", nav_links)
        self.assertIn("https://example.com/promo/popup", nav_links)
        self.assertIn("https://example.com/redirect/login", nav_links)
        self.assertIn("https://example.com/quick-link", nav_links)

    def test_meta_refresh(self):
        """Tests <meta http-equiv="refresh" content="N;url=..."> parsing."""
        html = """
        <meta http-equiv="refresh" content="5;url=/session/timeout">
        """
        nav_links, _, _, _ = DOMExtractor.extract(html, self.PAGE_URL)
        self.assertIn("https://example.com/session/timeout", nav_links)

    def test_link_preload_prefetch(self):
        """Tests script preloads vs asset preloads."""
        html = """
        <link rel="preload" href="/static/app.js" as="script">
        <link rel="prefetch" href="/static/chunk1.js">
        <link rel="modulepreload" href="/static/module.js">
        <link rel="preload" href="/fonts/font.woff2" as="font">
        <link rel="stylesheet" href="/css/styles.css">
        <link rel="canonical" href="/canonical-page">
        """
        nav_links, script_urls, asset_urls, _ = DOMExtractor.extract(
            html, self.PAGE_URL
        )

        self.assertIn("https://example.com/static/app.js", script_urls)
        self.assertIn("https://example.com/static/chunk1.js", script_urls)
        self.assertIn("https://example.com/static/module.js", script_urls)

        self.assertIn("https://example.com/fonts/font.woff2", asset_urls)
        self.assertIn("https://example.com/css/styles.css", asset_urls)

        self.assertIn("https://example.com/canonical-page", nav_links)


class TestFormExtractor(unittest.TestCase):
    """Test suite for FormExtractor and FormPayloadGenerator."""

    PAGE_URL = "https://example.com/app/forms.html"

    def test_form_get_extraction(self):
        """Tests GET form extraction with query parameter locations."""
        html = """
        <form action="/search" method="GET">
            <input type="search" name="q" required>
            <input type="number" name="page" value="2">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)

        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        self.assertEqual(ep.path, "/search")
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.base_url, "https://example.com")
        self.assertIsNone(ep.request_body_sample)
        self.assertEqual(ep.headers, {})

        param_map = {p.name: p for p in ep.parameters}
        self.assertIn("q", param_map)
        self.assertIn("page", param_map)
        self.assertEqual(param_map["q"].location, "query")
        self.assertTrue(param_map["q"].required)
        self.assertEqual(param_map["page"].location, "query")
        self.assertEqual(param_map["page"].param_type, "integer")
        self.assertEqual(param_map["page"].example, 2)

    def test_form_post_urlencoded(self):
        """Tests POST form extraction with x-www-form-urlencoded header and payload sample."""
        html = """
        <form action="/api/v1/auth/login" method="POST" enctype="application/x-www-form-urlencoded">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)

        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        self.assertEqual(ep.path, "/api/v1/auth/login")
        self.assertEqual(ep.method, "POST")
        self.assertEqual(
            ep.headers.get("Content-Type"), "application/x-www-form-urlencoded"
        )
        self.assertIsNotNone(ep.request_body_sample)
        self.assertEqual(ep.request_body_sample.get("username"), "crawler_user")
        self.assertEqual(ep.request_body_sample.get("password"), "ApiToolTest123!")

        for p in ep.parameters:
            self.assertEqual(p.location, "body")
            self.assertTrue(p.required)

    def test_form_post_multipart(self):
        """Tests POST form extraction with multipart/form-data."""
        html = """
        <form action="/api/v1/media/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="attachment" required>
            <input type="text" name="caption">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)

        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        self.assertEqual(ep.headers.get("Content-Type"), "multipart/form-data")
        self.assertIn("attachment", ep.request_body_sample)
        self.assertEqual(ep.request_body_sample["attachment"], "sample_upload.txt")

    def test_hidden_method_override(self):
        """Tests hidden method overrides (_method, _http_method, x-http-method-override)."""
        html = """
        <form action="/api/v1/users/42" method="POST">
            <input type="hidden" name="_method" value="DELETE">
            <input type="text" name="reason">
        </form>
        <form action="/api/v1/users/42" method="POST">
            <input type="hidden" name="x-http-method-override" value="PATCH">
            <input type="text" name="status">
        </form>
        <form action="/api/v1/users/42" method="POST">
            <input type="hidden" name="_http_method" value="PUT">
            <input type="text" name="name">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)

        self.assertEqual(len(endpoints), 3)
        self.assertEqual(endpoints[0].method, "DELETE")
        self.assertEqual(endpoints[1].method, "PATCH")
        self.assertEqual(endpoints[2].method, "PUT")

    def test_input_type_dummy_fills(self):
        """Tests realistic dummy fills synthesized by FormPayloadGenerator for all required types."""
        html = """
        <form action="/api/v1/test-types" method="POST">
            <input type="email" name="user_email">
            <input type="password" name="user_password">
            <input type="tel" name="user_phone">
            <input type="number" name="user_number">
            <input type="url" name="user_website">
            <input type="date" name="user_birthdate">
            <input type="search" name="search_term">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)
        self.assertEqual(len(endpoints), 1)

        payload = endpoints[0].request_body_sample
        self.assertEqual(payload["user_email"], "crawler@example.com")
        self.assertEqual(payload["user_password"], "ApiToolTest123!")
        self.assertIn("555", payload["user_phone"])
        self.assertEqual(payload["user_number"], 1)
        self.assertEqual(payload["user_website"], "https://example.com")
        self.assertEqual(payload["user_birthdate"], "2026-01-01")
        self.assertEqual(payload["search_term"], "test search")

    def test_formaction_and_formmethod_button_override(self):
        """Tests HTML5 submit button formaction and formmethod overrides creating distinct endpoints."""
        html = """
        <form action="/articles/save" method="POST">
            <input type="text" name="title" value="My Draft">
            <button type="submit">Save</button>
            <button type="submit" formaction="/articles/draft" formmethod="POST">Save Draft</button>
            <button type="submit" formaction="/articles/preview" formmethod="GET">Preview</button>
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)

        self.assertEqual(len(endpoints), 3)

        ep_save = next(e for e in endpoints if e.path == "/articles/save")
        self.assertEqual(ep_save.method, "POST")
        self.assertEqual(
            ep_save.headers.get("Content-Type"),
            "application/x-www-form-urlencoded",
        )
        self.assertIsNotNone(ep_save.request_body_sample)

        ep_draft = next(e for e in endpoints if e.path == "/articles/draft")
        self.assertEqual(ep_draft.method, "POST")
        self.assertEqual(
            ep_draft.headers.get("Content-Type"),
            "application/x-www-form-urlencoded",
        )
        self.assertIsNotNone(ep_draft.request_body_sample)

        ep_preview = next(e for e in endpoints if e.path == "/articles/preview")
        self.assertEqual(ep_preview.method, "GET")
        self.assertEqual(ep_preview.headers, {})
        self.assertIsNone(ep_preview.request_body_sample)
        for p in ep_preview.parameters:
            self.assertEqual(p.location, "query")

    def test_html5_external_controls(self):
        """Tests external controls linked via form attribute."""
        html = """
        <form id="profile-form" action="/profile/update" method="POST"></form>
        <input type="text" name="bio" form="profile-form">
        <button type="submit" form="profile-form">Save</button>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)
        self.assertEqual(len(endpoints), 1)
        self.assertIn("bio", endpoints[0].request_body_sample)

    def test_select_and_textarea_controls(self):
        """Tests select dropdown and textarea control parsing."""
        html = """
        <form action="/submit-comment" method="POST">
            <textarea name="comment">Custom text content</textarea>
            <select name="category">
                <option value="announcement">Announcement</option>
                <option value="feedback" selected>Feedback</option>
            </select>
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)
        self.assertEqual(len(endpoints), 1)
        payload = endpoints[0].request_body_sample
        self.assertEqual(payload["comment"], "Custom text content")
        self.assertEqual(payload["category"], "feedback")

    def test_empty_and_malformed_html(self):
        """Tests that empty and malformed HTML return empty collections without crashing."""
        nav, scripts, assets, htmx = DOMExtractor.extract("", self.PAGE_URL)
        self.assertEqual(nav, [])
        self.assertEqual(scripts, [])
        self.assertEqual(assets, [])
        self.assertEqual(htmx, [])

        forms = FormExtractor.extract("", self.PAGE_URL)
        self.assertEqual(forms, [])

        # HTML with ignored pseudo-protocols
        html_ignored = """
        <a href="javascript:void(0)">JS</a>
        <a href="mailto:test@example.com">Mail</a>
        <a href="tel:+1234567890">Tel</a>
        <a href="#section">Hash</a>
        <a href="">Empty</a>
        """
        nav, _, _, _ = DOMExtractor.extract(html_ignored, self.PAGE_URL)
        self.assertEqual(nav, [])

    def test_form_defaults(self):
        """Tests form with omitted action (defaults to page_url), omitted method (defaults to GET), and nameless inputs."""
        html = """
        <form>
            <input type="text" value="nameless-ignored">
            <input type="text" name="named_field" value="my_val">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)
        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.path, "/app/forms.html")
        self.assertEqual(ep.base_url, "https://example.com")
        self.assertEqual(len(ep.parameters), 1)
        self.assertEqual(ep.parameters[0].name, "named_field")

    def test_checkbox_and_radio_controls(self):
        """Tests checkbox and radio button parameters and payload generation."""
        html = """
        <form action="/survey" method="POST">
            <input type="checkbox" name="agree" value="yes" checked>
            <input type="radio" name="plan" value="pro" checked>
            <input type="radio" name="plan" value="free">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)
        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        self.assertEqual(ep.request_body_sample.get("agree"), "yes")
        self.assertEqual(ep.request_body_sample.get("plan"), "pro")

    def test_multiple_forms_page(self):
        """Tests multiple forms on a single page are all discovered as separate endpoints."""
        html = """
        <form action="/login" method="POST">
            <input type="text" name="user">
        </form>
        <form action="/register" method="POST">
            <input type="text" name="email">
        </form>
        """
        endpoints = FormExtractor.extract(html, self.PAGE_URL)
        self.assertEqual(len(endpoints), 2)
        paths = [e.path for e in endpoints]
        self.assertIn("/login", paths)
        self.assertIn("/register", paths)


if __name__ == "__main__":
    unittest.main()
