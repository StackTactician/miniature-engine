"""
Unit tests for Webpack 5, Webpack 4, Vite, and Next.js Chunk Map Cracker.
"""

import unittest
from api_tool.models import DiscoveredChunkManifest, ScanResult
from api_tool.analyzer.chunk_cracker import ChunkMapCracker
from api_tool.analyzer import ChunkMapCracker as ImportedCracker, DiscoveredChunkManifest as ImportedManifest


class TestDiscoveredChunkManifest(unittest.TestCase):
    """Tests for DiscoveredChunkManifest dataclass and ScanResult integration."""

    def test_manifest_creation_and_defaults(self):
        manifest = DiscoveredChunkManifest(framework="webpack5")
        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(manifest.source_script, "")
        self.assertEqual(manifest.base_url, "")
        self.assertEqual(manifest.chunk_urls, [])
        self.assertEqual(manifest.chunk_map, {})
        self.assertIsNone(manifest.template)
        self.assertEqual(manifest.metadata, {})

    def test_manifest_to_from_dict(self):
        original = DiscoveredChunkManifest(
            framework="vite",
            source_script="https://example.com/assets/index.js",
            base_url="https://example.com/",
            chunk_urls=["https://example.com/assets/chunk-1.js", "https://example.com/assets/chunk-2.js"],
            chunk_map={"chunk-1": "assets/chunk-1.js", "chunk-2": "assets/chunk-2.js"},
            template="assets/{name}.js",
            metadata={"total_chunks": 2},
        )
        data = original.to_dict()
        self.assertEqual(data["framework"], "vite")
        self.assertEqual(data["chunk_urls"], ["https://example.com/assets/chunk-1.js", "https://example.com/assets/chunk-2.js"])
        self.assertEqual(data["template"], "assets/{name}.js")

        restored = DiscoveredChunkManifest.from_dict(data)
        self.assertEqual(restored.framework, original.framework)
        self.assertEqual(restored.source_script, original.source_script)
        self.assertEqual(restored.base_url, original.base_url)
        self.assertEqual(restored.chunk_urls, original.chunk_urls)
        self.assertEqual(restored.chunk_map, original.chunk_map)
        self.assertEqual(restored.template, original.template)
        self.assertEqual(restored.metadata, original.metadata)

    def test_scan_result_integration(self):
        manifest = DiscoveredChunkManifest(
            framework="webpack5",
            chunk_urls=["https://example.com/static/js/100.abc.js"],
            chunk_map={"100": "100.abc.js"},
        )
        result = ScanResult(
            target_url="https://example.com",
            chunk_manifests=[manifest],
        )
        data = result.to_dict()
        self.assertIn("chunk_manifests", data)
        self.assertEqual(len(data["chunk_manifests"]), 1)
        self.assertEqual(data["chunk_manifests"][0]["framework"], "webpack5")
        self.assertEqual(data["chunk_manifests"][0]["chunk_urls"], ["https://example.com/static/js/100.abc.js"])


class TestWebpackCracker(unittest.TestCase):
    """Tests for Webpack 4 & 5 chunk extraction."""

    def setUp(self):
        self.cracker = ChunkMapCracker(base_asset_url="https://app.example.com/")

    def test_webpack5_standard_minified_u(self):
        js = """
        !function() {
            var n = {};
            n.p = "/static/js/";
            n.u = function(e) {
                return "" + e + "." + {
                    101: "a1b2c3d4",
                    202: "e5f6a7b8",
                    303: "9c8b7a6f"
                }[e] + ".chunk.js"
            };
        }();
        """
        manifest = self.cracker.crack(js, source_script="https://app.example.com/static/js/runtime.js")
        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(manifest.source_script, "https://app.example.com/static/js/runtime.js")
        self.assertIn("101", manifest.chunk_map)
        self.assertIn("202", manifest.chunk_map)
        self.assertIn("303", manifest.chunk_map)

        # Check filenames
        self.assertEqual(manifest.chunk_map["101"], "101.a1b2c3d4.chunk.js")
        self.assertEqual(manifest.chunk_map["202"], "202.e5f6a7b8.chunk.js")

        # Check resolved URLs with base_asset_url and publicPath
        expected_url = "https://app.example.com/static/js/101.a1b2c3d4.chunk.js"
        self.assertIn(expected_url, manifest.chunk_urls)
        self.assertEqual(len(manifest.chunk_urls), 3)

    def test_webpack5_arrow_function(self):
        js = """
        n.p = "";
        n.u = e => "chunks/" + e + "." + { 10: "deadbeef", 20: "cafebabe" }[e] + ".js";
        """
        manifest = ChunkMapCracker.crack(js, base_asset_url="https://app.example.com/dist/")
        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(manifest.chunk_map["10"], "chunks/10.deadbeef.js")
        self.assertEqual(manifest.chunk_map["20"], "chunks/20.cafebabe.js")
        self.assertIn("https://app.example.com/dist/chunks/10.deadbeef.js", manifest.chunk_urls)

    def test_webpack5_name_and_hash_maps(self):
        js = """
        r.u = function(e) {
            return "static/js/" + ({ 10: "dashboard", 20: "settings" }[e] || e) + "." + {
                10: "c3d4e5f6",
                20: "a7b8c9d0",
                30: "11223344"
            }[e] + ".chunk.js"
        }
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(manifest.chunk_map["10"], "static/js/dashboard.c3d4e5f6.chunk.js")
        self.assertEqual(manifest.chunk_map["20"], "static/js/settings.a7b8c9d0.chunk.js")
        self.assertEqual(manifest.chunk_map["30"], "static/js/30.11223344.chunk.js")
        self.assertIn("https://app.example.com/static/js/dashboard.c3d4e5f6.chunk.js", manifest.chunk_urls)

    def test_webpack5_ternary_expressions(self):
        js = """
        n.u = function(e) {
            return 100 === e ? "static/chunks/admin.bundle.js" : 200 === e ? "static/chunks/vendor.bundle.js" : "" + e + "." + { 300: "aabbcc" }[e] + ".chunk.js";
        };
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(manifest.chunk_map["100"], "static/chunks/admin.bundle.js")
        self.assertEqual(manifest.chunk_map["200"], "static/chunks/vendor.bundle.js")
        self.assertEqual(manifest.chunk_map["300"], "300.aabbcc.chunk.js")
        self.assertIn("https://app.example.com/static/chunks/admin.bundle.js", manifest.chunk_urls)

    def test_webpack4_jsonp_script_src(self):
        js = """
        function jsonpScriptSrc(chunkId) {
            return n.p + "static/js/" + ({ 1: "main", 2: "vendor" }[chunkId] || chunkId) + "." + {
                1: "deadbeef",
                2: "cafebabe"
            }[chunkId] + ".chunk.js";
        }
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "webpack4")
        self.assertEqual(manifest.chunk_map["1"], "static/js/main.deadbeef.chunk.js")
        self.assertEqual(manifest.chunk_map["2"], "static/js/vendor.cafebabe.chunk.js")
        self.assertIn("https://app.example.com/static/js/main.deadbeef.chunk.js", manifest.chunk_urls)

    def test_webpack_installed_chunks_fallback(self):
        js = """
        var installedChunks = { 10: 0, 20: 0, 30: 0 };
        function install() {}
        """
        manifest = self.cracker.crack(js)
        self.assertIn(manifest.framework, ("webpack4", "webpack5"))
        self.assertIn("10", manifest.chunk_map)
        self.assertIn("https://app.example.com/10.js", manifest.chunk_urls)


class TestViteCracker(unittest.TestCase):
    """Tests for Vite dynamic import map cracking."""

    def setUp(self):
        self.cracker = ChunkMapCracker(base_asset_url="https://vite.example.com/app/")

    def test_vite_map_deps_array(self):
        js = """
        const __vite__mapDeps = [
            "assets/chunk-index-38a9bc12.js",
            "assets/chunk-vendor-90cd12ef.js",
            "assets/chunk-auth-45ab67cd.js"
        ];
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "vite")
        self.assertEqual(len(manifest.chunk_urls), 3)
        self.assertIn("https://vite.example.com/app/assets/chunk-index-38a9bc12.js", manifest.chunk_urls)
        self.assertIn("chunk-auth-45ab67cd.js", manifest.chunk_map)

    def test_vite_preload_helper_function(self):
        js = """
        const __vite__mapDeps = (i, m = __vite__mapDeps, d = (m.f || (m.f = [
            "assets/Page1-a1b2c3.js",
            "assets/Page2-d4e5f6.js"
        ]))) => i.map(i => d[i]);
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "vite")
        self.assertEqual(len(manifest.chunk_urls), 2)
        self.assertIn("https://vite.example.com/app/assets/Page1-a1b2c3.js", manifest.chunk_urls)

    def test_vite_preload_call(self):
        js = """
        const t = () => import("./assets/Module-1.js");
        __vitePreload(t, true ? ["assets/Module-1.js", "assets/vendor-common.js"] : void 0);
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "vite")
        self.assertIn("https://vite.example.com/app/assets/Module-1.js", manifest.chunk_urls)
        self.assertIn("https://vite.example.com/app/assets/vendor-common.js", manifest.chunk_urls)

    def test_vite_json_manifest(self):
        manifest_json = """
        {
            "src/main.ts": {
                "file": "assets/main-1234.js",
                "src": "src/main.ts",
                "isEntry": true,
                "dynamicImports": ["src/views/About.vue"]
            },
            "src/views/About.vue": {
                "file": "assets/About-5678.js",
                "src": "src/views/About.vue"
            }
        }
        """
        manifest = self.cracker.crack(manifest_json)
        self.assertEqual(manifest.framework, "vite")
        self.assertEqual(len(manifest.chunk_urls), 2)
        self.assertIn("https://vite.example.com/app/assets/main-1234.js", manifest.chunk_urls)
        self.assertIn("https://vite.example.com/app/assets/About-5678.js", manifest.chunk_urls)


class TestNextJsCracker(unittest.TestCase):
    """Tests for Next.js build manifest cracking."""

    def setUp(self):
        self.cracker = ChunkMapCracker(base_asset_url="https://nextjs.example.com/")

    def test_nextjs_direct_build_manifest(self):
        js = """
        self.__BUILD_MANIFEST = {
            __rewrites: { beforeFiles: [], afterFiles: [], fallback: [] },
            "/": [
                "static/chunks/pages/index-abcdef123.js"
            ],
            "/about": [
                "static/chunks/pages/about-456789abc.js"
            ],
            "/_error": [
                "static/chunks/pages/_error-11223344.js"
            ],
            sortedPages: ["/", "/about", "/_error"]
        };
        self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB();
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "nextjs")
        self.assertIn("/", manifest.chunk_map)
        self.assertIn("/about", manifest.chunk_map)
        self.assertIn("https://nextjs.example.com/static/chunks/pages/index-abcdef123.js", manifest.chunk_urls)
        self.assertIn("https://nextjs.example.com/static/chunks/pages/about-456789abc.js", manifest.chunk_urls)
        self.assertEqual(len(manifest.chunk_urls), 3)

    def test_nextjs_iife_wrapper_build_manifest(self):
        js = """
        (self.__BUILD_MANIFEST = (function(s, a, b) {
            return {
                __rewrites: { beforeFiles: [], afterFiles: [], fallback: [] },
                "/": [s, a],
                "/dashboard": [s, b],
                sortedPages: ["/", "/dashboard"]
            };
        })(
            "static/chunks/main-common.js",
            "static/chunks/pages/index.js",
            "static/chunks/pages/dashboard.js"
        ))
        """
        manifest = self.cracker.crack(js)
        self.assertEqual(manifest.framework, "nextjs")
        self.assertIn("https://nextjs.example.com/static/chunks/main-common.js", manifest.chunk_urls)
        self.assertIn("https://nextjs.example.com/static/chunks/pages/index.js", manifest.chunk_urls)
        self.assertIn("https://nextjs.example.com/static/chunks/pages/dashboard.js", manifest.chunk_urls)
        self.assertEqual(len(manifest.chunk_urls), 3)


class TestEdgeCasesAndSafety(unittest.TestCase):
    """Tests for resilience, empty inputs, exports, and edge cases."""

    def test_empty_and_unknown_content(self):
        cracker = ChunkMapCracker()
        m1 = cracker.crack("")
        self.assertEqual(m1.framework, "unknown")
        self.assertEqual(m1.chunk_urls, [])

        m2 = cracker.crack("console.log('hello world');")
        self.assertEqual(m2.framework, "unknown")
        self.assertEqual(m2.chunk_urls, [])

    def test_exports_from_analyzer_init(self):
        self.assertIs(ImportedCracker, ChunkMapCracker)
        self.assertIs(ImportedManifest, DiscoveredChunkManifest)

    def test_crack_all_multiple_manifests(self):
        js = """
        self.__BUILD_MANIFEST = { "/": ["static/chunks/pages/index.js"] };
        const __vite__mapDeps = ["assets/chunk-1.js"];
        """
        cracker = ChunkMapCracker(base_asset_url="https://example.com/")
        manifests = cracker.crack_all(js)
        self.assertGreaterEqual(len(manifests), 2)
        frameworks = [m.framework for m in manifests]
        self.assertIn("nextjs", frameworks)
        self.assertIn("vite", frameworks)

    def test_url_resolution_already_absolute(self):
        js = """
        const __vite__mapDeps = [
            "https://cdn.other.com/assets/remote-chunk.js"
        ];
        """
        manifest = ChunkMapCracker.crack(js, base_asset_url="https://example.com/")
        self.assertEqual(manifest.chunk_urls, ["https://cdn.other.com/assets/remote-chunk.js"])

    def test_webpack5_es6_template_literal(self):
        js = "n.u = e => `static/chunks/${e}.${{ 10: 'deadbeef', 20: 'cafebabe' }[e]}.js`;"
        manifest = ChunkMapCracker.crack(js, base_asset_url="https://example.com/")
        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(manifest.chunk_map["10"], "static/chunks/10.deadbeef.js")
        self.assertEqual(manifest.chunk_map["20"], "static/chunks/20.cafebabe.js")
        self.assertIn("https://example.com/static/chunks/10.deadbeef.js", manifest.chunk_urls)

    def test_stress_1000_chunks_benchmark(self):
        import time
        # Generate Webpack runtime with 1000 chunk mappings
        chunks = {str(i): f"hash{i:04d}" for i in range(1000)}
        chunks_js = ", ".join(f"{k}: '{v}'" for k, v in chunks.items())
        js = f"""
        n.p = "/assets/";
        n.u = function(e) {{
            return "" + e + "." + {{ {chunks_js} }}[e] + ".chunk.js";
        }};
        """
        start = time.perf_counter()
        manifest = ChunkMapCracker.crack(js, base_asset_url="https://cdn.example.com")
        duration = time.perf_counter() - start

        self.assertEqual(manifest.framework, "webpack5")
        self.assertEqual(len(manifest.chunk_urls), 1000)
        self.assertLess(duration, 0.5, f"Cracking 1000 chunks took {duration:.4f}s, expected < 0.5s")

    def test_redos_safety_adversarial_input(self):
        import time
        # Craft adversarial inputs designed to trigger exponential backtracking
        adversarial_input = "n.u = function(e) { return " + "(((" * 50 + "e" + ")))" * 50 + " + {'key': 'val'}; }"
        start = time.perf_counter()
        manifest = ChunkMapCracker.crack(adversarial_input)
        duration = time.perf_counter() - start
        self.assertLess(duration, 0.05, f"Adversarial ReDoS test took {duration:.4f}s, expected < 0.05s")


if __name__ == "__main__":
    unittest.main()

