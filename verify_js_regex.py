"""
Quick verification script for JSRegexExtractor.
Verifies imports from api_tool.models and executes test assertions across:
1. REST endpoint candidate extraction and path normalization
2. Path parameters (:id, ${id}, {id}, [id])
3. Query string parameters
4. Multi-stage false-positive filter (SVG, Tailwind, MIME, UUID, dates, base64, static assets)
5. Client configs (Axios, Ky, ofetch, Wretch, tRPC, inlined env vars)
6. Next.js Server Actions (createServerReference, Next-Action header)
"""

import sys
from api_tool.models import DiscoveredEndpoint, DiscoveredParameter
from api_tool.analyzer.js_regex import JSRegexExtractor

def run_verification():
    extractor = JSRegexExtractor()
    print("1. Verifying models import and instantiation...")
    ep_dummy = DiscoveredEndpoint(path="/test", method="GET")
    param_dummy = DiscoveredParameter(name="id", location="path")
    assert isinstance(ep_dummy, DiscoveredEndpoint)
    assert isinstance(param_dummy, DiscoveredParameter)
    print("   [PASS] Models imported and instantiated successfully.")

    print("2. Verifying REST endpoint candidate extraction & path parameters...")
    sample_js = """
    // REST candidates & path params
    const u1 = await fetch('/api/v1/users/:userId/orders');
    const u2 = await axios.post("/api/v2/items/${itemId}/update", data);
    const u3 = await fetch('/api/v3/products/{productId}?inStock=true&limit=50');
    const u4 = await ky.delete('/v1/accounts/[accountId]');
    const u5 = await fetch('https://api.external.com/v1/auth/token');
    
    // False positives to filter out
    const d = "M10 20L30 40Z";
    const xmlns = "http://www.w3.org/2000/svg";
    const tw = "w-1/2 aspect-16/9 bg-red-500/50 text-black/75";
    const mime = "application/json";
    const uuid = "123e4567-e89b-12d3-a456-426614174000";
    const date = "2026/09/30";
    const b64 = "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////";
    const icon = "/images/logo.png";
    """
    discovered = extractor.extract_endpoints(sample_js)
    assert len(discovered) == 5, f"Expected 5 endpoints, got {len(discovered)}"

    ep_map = {e.path: e for e in discovered}
    assert "/api/v1/users/{userId}/orders" in ep_map
    assert "/api/v2/items/{itemId}/update" in ep_map
    assert "/api/v3/products/{productId}?inStock=true&limit=50" in ep_map
    assert "/v1/accounts/{accountId}" in ep_map
    assert "/v1/auth/token" in ep_map

    # Check parameter types and locations
    ep_query = ep_map["/api/v3/products/{productId}?inStock=true&limit=50"]
    param_names = {p.name: p for p in ep_query.parameters}
    assert "productId" in param_names and param_names["productId"].location == "path"
    assert "inStock" in param_names and param_names["inStock"].location == "query"
    assert "limit" in param_names and param_names["limit"].location == "query"
    assert ep_query.parameters[1].example == "true" or ep_query.parameters[2].example == "50"
    print("   [PASS] REST endpoints, path parameters, and query parameters verified.")

    print("3. Verifying HTTP client configuration discovery...")
    config_js = """
    const c1 = axios.create({ baseURL: "https://axios-api.com/v1" });
    axios.defaults.baseURL = "https://axios-defaults.com";
    const c2 = ky.create({ prefixUrl: "https://ky-api.com" });
    const c3 = ofetch.create({ baseURL: "https://ofetch-api.com" });
    const c4 = wretch("https://wretch-api.com");
    const c5 = httpBatchLink({ url: "https://trpc-api.com/trpc" });
    const env = { NEXT_PUBLIC_API_URL: "https://next-api.com", VITE_API_URL: "https://vite-api.com" };
    """
    configs = extractor.extract_client_configs(config_js)
    assert "https://axios-api.com/v1" in configs["axios"]
    assert "https://axios-defaults.com" in configs["axios"]
    assert "https://ky-api.com" in configs["ky"]
    assert "https://ofetch-api.com" in configs["ofetch"]
    assert "https://wretch-api.com" in configs["wretch"]
    assert "https://trpc-api.com/trpc" in configs["trpc"]
    assert configs["env_vars"]["NEXT_PUBLIC_API_URL"] == "https://next-api.com"
    assert configs["env_vars"]["VITE_API_URL"] == "https://vite-api.com"
    assert len(configs["base_urls"]) >= 7
    print("   [PASS] Client configs (Axios, Ky, ofetch, Wretch, tRPC, env vars) verified.")

    print("4. Verifying Next.js Server Actions extraction...")
    sa_js = """
    export const act1 = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", callServer);
    const act2 = (0, r.createServerReference)("c0ffee1234567890abcdef1234567890abcdef12", s);
    """
    server_actions = extractor.extract_server_actions(sa_js, page_route="/checkout")
    assert len(server_actions) == 2, f"Expected 2 server actions, got {len(server_actions)}"
    action_headers = [sa.headers.get("Next-Action") for sa in server_actions]
    assert "40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f" in action_headers
    assert "c0ffee1234567890abcdef1234567890abcdef12" in action_headers
    for sa in server_actions:
        assert sa.path == "/checkout"
        assert sa.method == "POST"
        assert "server_action" in sa.tags
    print("   [PASS] Next.js Server Actions verified.")

    print("\nALL JSRegexExtractor VERIFICATIONS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_verification()
