# Research Report: 2026-Era JavaScript Bundle Structures, Source Map V3 Nuances, Modern GraphQL Patterns & False-Positive Filtering

This research report provides actionable specifications, concrete regular expressions, comprehensive test cases, and architectural designs for implementing the **Static Analysis Module** (Module 2) in `api_tool`.

---

## 1. Modern 2026 Bundler Output Structures & API Base URL Embedding

### A. Framework-by-Framework Bundle Layout & URL Embedding

#### 1. Next.js 14 / 15 (App Router with Turbopack & Webpack 5)
* **Environment Variables (`process.env.NEXT_PUBLIC_*`):**
  * Turbopack and Webpack statically inline any environment variable prefixed with `NEXT_PUBLIC_` during compilation.
  * In production bundles, these appear either as raw string constants (e.g., `"https://api.acme.com/v1"`) or as inlined objects:
    ```javascript
    const API_BASE = "https://api.acme.com/v1";
    // or minified object property assignment:
    {NEXT_PUBLIC_API_URL:"https://api.acme.com/v1",NEXT_PUBLIC_AUTH_DOMAIN:"auth.acme.com"}
    ```
* **Turbopack Chunk Structure:**
  * Client bundles reside under `/_next/static/chunks/app/...` and `/_next/static/chunks/[hash].js`.
  * Turbopack enforces chunk grouping heuristics (`minChunkSize` ~50KB, `maxChunkCountPerGroup` ~40).
  * Global module runtime identifiers: `self.__turbopack_load__`, `globalThis.__turbopack_require__`, or `self.__react_server_dom_turbopack__`.
* **Server Actions (`'use server'` directives):**
  * Server Actions are *never* bundled into client code. Instead, the compiler transforms them into **client reference stubs** using `createServerReference`:
    ```javascript
    // Unminified:
    export const updateUser = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", callServer);
    // Minified (Turbopack / Webpack):
    (0, r.createServerReference)("c0ffee1234567890abcdef1234567890abcdef12", s)
    ```
  * Calling a Server Action triggers an HTTP `POST` request to the current page route (or `/_next/action`) with the request header:
    `Next-Action: <40_hex_char_action_id>`.
    Extracting these IDs allows direct black-box discovery and testing of Server Actions.
* **RSC Flight Stream & Manifests:**
  * Initial HTML streams flight data in script tags: `self.__next_f.push([1, "..."])`.
  * Server references and action mappings are cataloged in `server-reference-manifest.json` and `middleware-manifest.json`.

#### 2. Vite 5 & 6 (Rollup / Rolldown Engine)
* **Environment Variables (`import.meta.env.*`):**
  * Vite replaces `import.meta.env.VITE_*` and `import.meta.env.BASE_URL` with static string literals.
  * Example source: `fetch(`${import.meta.env.VITE_API_URL}/users`)`
  * Bundle output: `fetch("https://api.acme.com/users")` or `fetch("".concat("https://api.acme.com", "/users"))`.
* **Base URL:**
  * Configured via `base` in `vite.config.ts`. Exposed in client code as `import.meta.env.BASE_URL` (defaults to `/`).
* **Asset Structure:**
  * Output files are placed in `/assets/[name]-[hash].js` and CSS in `/assets/[name]-[hash].css`.

#### 3. Webpack 5
* **Public Path & Chunk Loading:**
  * `__webpack_require__.p = "/static/"` or `__webpack_public_path__`.
  * Dynamic chunks loaded via `__webpack_require__.e(chunkId)`.
* **Axios & HTTP Clients:**
  * Axios instances:
    ```javascript
    // Unminified:
    const client = axios.create({ baseURL: "https://api.acme.com/v2", timeout: 5000 });
    // Minified:
    n.create({baseURL:"https://api.acme.com/v2",timeout:5e3})
    // Axios defaults:
    a.defaults.baseURL = "https://api.acme.com/v2"
    ```
* **Modern Fetch Wrappers (Ky, ofetch, Wretch):**
  * Ky: `ky.create({ prefixUrl: "https://api.acme.com" })` or `k.create({prefixUrl:"/api"})`
  * ofetch (Nuxt 3): `$fetch.create({ baseURL: "/api/v1" })`
  * Wretch: `wretch("https://api.acme.com").get("/users")`
  * tRPC: `httpBatchLink({ url: "https://api.acme.com/trpc" })`

#### 4. Bun Bundler (`bun build`) & esbuild
* Both inline `process.env.*` values statically at build time.
* Emit modern ES2022+ syntax (native private fields `#privateProp`, optional chaining `?.`, nullish coalescing `??`).
* Place source map comments at the very end of chunk files.

---

## 2. Source Map V3 Nuances & Path Traversal Security

### A. Structure of Source Map V3
The Source Map V3 JSON document has the following schema:
```json
{
  "version": 3,
  "file": "app.bundle.js",
  "sourceRoot": "",
  "sources": [
    "webpack:///src/api/auth.ts",
    "turbopack:///[project]/src/utils/http.ts",
    "../src/components/Dashboard.tsx"
  ],
  "sourcesContent": [
    "export const login = (user, pass) => fetch('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ user, pass }) });",
    "export const BASE_API = 'https://internal-api.corp/v1';",
    "export const Dashboard = () => <div>Dashboard</div>;"
  ],
  "names": ["login", "fetch", "BASE_API"],
  "mappings": "AAAA,IAAMA,GAAG,GAAG..."
}
```

#### Crucial Extraction Nuance: `sourcesContent`
* **Zero Network Requests Required:** When `sourcesContent` is populated, **each entry in `sourcesContent` contains the verbatim, raw TypeScript/JSX source code** corresponding to the file path at the same index in `sources`.
* Static analysis can parse original source code (unminified, complete with comments, internal API endpoints, and private route definitions) directly from memory without writing to disk.

#### Index Maps (`sections`)
When multiple source maps are concatenated into a single master bundle, an **Index Map** is generated instead of standard `mappings`:
```json
{
  "version": 3,
  "file": "master.bundle.js",
  "sections": [
    {
      "offset": { "line": 0, "column": 0 },
      "map": {
        "version": 3,
        "sources": ["foo.ts"],
        "sourcesContent": ["const x = 1;"]
      }
    },
    {
      "offset": { "line": 1500, "column": 0 },
      "url": "chunks/chunk2.js.map"
    }
  ]
}
```
* **Parser Requirement:** A robust source map engine must check if `"sections"` exists. If present, iterate over each section:
  * If `"map"` is present: recursively process the inline source map object.
  * If `"url"` is present: resolve the URL relative to the index map's base URL and fetch the child map.

---

### B. Safe Path Sanitization (Path Traversal / Zip Slip Prevention)

To extract or catalog original files safely:
1. **Strip Virtual Schemes & Prefixes:**
   Remove bundler virtual protocol prefixes:
   `webpack:///`, `webpack-internal:///`, `turbopack:///[project]/`, `ng:///`, `vite://`, `file:///`, `http://`, `https://`.
2. **Normalize Slashes & Drive Letters:**
   Convert Windows backslashes `\` to `/`. Strip Windows drive letters (`C:/` or `D:\`).
3. **Strip Control Characters & Null Bytes:**
   Remove `\x00` and non-printable characters.
4. **Tokenize & Filter Path Components:**
   Split the path by `/`. Discard any `.` (current dir) and `..` (parent traversal) components. **Never** use naive string replacement (e.g., `path.replace("../", "")`), as `....//` will bypass it.
5. **Filter Windows Reserved Device Filenames:**
   Reject or rename reserved Windows names: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`.
6. **Canonical Path Verification:**
   Before writing any file to disk, compute the canonical absolute destination path using `os.path.realpath(os.path.join(safe_root_dir, sanitized_path))` and verify:
   ```python
   assert os.path.commonpath([safe_root_dir, canonical_path]) == safe_root_dir
   ```

---

## 3. Modern Frontend GraphQL Conventions

### A. Client Libraries & Implementations

1. **Apollo Client (`@apollo/client`):**
   * Uses `gql` tagged template literal:
     ```javascript
     const GET_USER_QUERY = gql`
       query GetUserProfile($id: ID!) {
         user(id: $id) { id name email role }
       }
     `;
     ```
   * Client initialization: `new ApolloClient({ uri: '/graphql' })` or `createHttpLink({ uri: 'https://api.acme.com/graphql' })`.
2. **urql (`urql` / `@urql/core`):**
   * Uses `gql` tag or standard string templates with `createClient({ url: 'https://api.acme.com/graphql' })`.
3. **TanStack Query + `graphql-request`:**
   * Uses `request(endpoint, query, variables)` or `new GraphQLClient('/api/graphql')`.
4. **Relay (`react-relay`):**
   * Uses `graphql` tagged template literal:
     ```javascript
     const UserQuery = graphql`
       query UserQuery($userId: ID!) {
         node(id: $userId) { ...UserFragment }
       }
     `;
     ```

---

### B. Pre-compiled DocumentNodes & @graphql-codegen Nuance

In modern production bundles, developers frequently precompile GraphQL queries into **Abstract Syntax Tree (AST) JSON objects** at build time (`TypedDocumentNode`, `@graphql-codegen/client-preset`):
```javascript
// Precompiled TypedDocumentNode AST:
const GetUsersDocument = {
  kind: "Document",
  definitions: [{
    kind: "OperationDefinition",
    operation: "query",
    name: { kind: "Name", value: "GetUsers" },
    variableDefinitions: [{
      kind: "VariableDefinition",
      variable: { kind: "Variable", name: { kind: "Name", value: "limit" } }
    }],
    selectionSet: {
      kind: "SelectionSet",
      selections: [{
        kind: "Field",
        name: { kind: "Name", value: "users" },
        selectionSet: {
          kind: "SelectionSet",
          selections: [
            { kind: "Field", name: { kind: "Name", value: "id" } },
            { kind: "Field", name: { kind: "Name", value: "name" } }
          ]
        }
      }]
    }
  }]
};
```
* **Discovery Requirement:** The static analysis engine must scan for both:
  1. Tagged template literals & inline comments (`gql\`...```, `graphql\`...```, `/* GraphQL */`, `#graphql`).
  2. Compiled AST object signatures (`kind: "OperationDefinition"`, `operation: "query|mutation|subscription"`, `name: { value: "..." }`).

---

## 4. Modern False-Positive Link Filtering: Root-Cause Taxonomy

| False-Positive Category | Real-World JS Code Snippet | Why Naive Regex Triggers | Filtering Signature / Regex Pattern |
| :--- | :--- | :--- | :--- |
| **SVG Path Data** | `d="M10 20L30 40Z"` or `d="M0,0H24V24H0z"` | Matches path-like character chains with slashes/commas. | Starts with SVG path command `^[MmLlHhVvCcSsQqTtAa]`, followed by coordinate sequences. |
| **SVG XMLNS / URLs** | `xmlns="http://www.w3.org/2000/svg"` | Flags the standard XML namespace as an active API endpoint. | Exact match: `http://www.w3.org/2000/svg` or `http://www.w3.org/1999/xlink`. |
| **Tailwind Fractions** | `class="w-1/2 inset-x-1/2 translate-x-1/2 aspect-16/9"` | Interprets `1/2` or `16/9` as a relative path `/2` or `/9`. | `-(?:[1-9]\d*)/(?:[1-9]\d*)` (e.g. `w-1/2`, `translate-x-1/2`, `aspect-16/9`). |
| **Tailwind Opacity** | `class="bg-red-500/50 text-black/75 border-white/20"` | The `/50` opacity modifier is misclassified as a path. | `(?:bg\|text\|border\|ring\|divide)-[a-z]+(?:-[0-9]+)?/[0-9]+` |
| **CSS Modules / BEM** | `styles._header_1x8q9_12` or `btn--primary__icon` | Identifiers with underscores/dashes trigger loose regexes. | `^[a-zA-Z0-9_-]+__[a-zA-Z0-9_-]+` or `^_[a-zA-Z0-9_-]+_\d+$`. |
| **MIME Types** | `"application/json"`, `"image/svg+xml"`, `"text/html"` | Slashes between type and subtype mimic URL paths (`/json`). | Matches standard IANA MIME structure: `^(?:application\|audio\|font\|image\|text\|video)/[a-zA-Z0-9.+_-]+$`. |
| **UUIDs / GUIDs** | `"123e4567-e89b-12d3-a456-426614174000"` | Hex characters with dashes trigger slug/parameter matchers. | `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`. |
| **Date Formats** | `"YYYY/MM/DD"`, `"2026/09/30"`, `"2026-09-30T12:00:00Z"` | Date separators (`/`) mimic resource directory hierarchies. | `^(?:\d{4}[/-]\d{2}[/-]\d{2}\|(?:YYYY\|MM\|DD)[/-](?:YYYY\|MM\|DD)[/-](?:YYYY\|MM\|DD))`. |
| **AST Node Types** | `"Identifier/Literal"`, `"MemberExpression/Call"` | Slashes in compiler/linter AST tables mimic endpoints. | `^(?:Identifier\|Literal\|MemberExpression\|CallExpression)/[A-Za-z]+$`. |
| **Base64 Data Chunks** | `"iVBORw0KGgoAAAANSUhEUgAAAA..."` | Base64 strings contain `/` characters (e.g. `/9j/4AAQ...`). | High entropy strings matching base64 format without protocol. |

---

## 5. Concrete Regular Expressions (Production-Ready Python)

```python
import re

# Base URL & API Client Configurations
AXIOS_BASEURL_PATTERN = re.compile(
    r"""(?:\.create|\baxios)\s*\(\s*\{[^{}]*?["']?baseURL["']?\s*:\s*["'`](https?://[^"'`\s]+|/[^"'`\s]*)["'`][^{}]*?\}""",
    re.IGNORECASE
)

FETCH_CLIENT_PATTERN = re.compile(
    r"""(?:prefixUrl|baseURL|apiUrl|baseUrl|base_url)\s*:\s*["'`](https?://[^"'`\s]+|/[^"'`\s]*)["'`]|wretch\s*\(\s*["'`](https?://[^"'`\s]+|/[^"'`\s]*)["'`]""",
    re.IGNORECASE
)

NEXT_SERVER_ACTION_PATTERN = re.compile(
    r"""(?:\bcreateServerReference|\(0\s*,\s*[^)]*\.createServerReference\))\s*\(\s*["']([a-f0-9]{40}|[a-zA-Z0-9_\-\.\/]+#[a-zA-Z0-9_]+)["']"""
)

INLINE_ENV_VAR_PATTERN = re.compile(
    r"""(?:(?:process\.env\.NEXT_PUBLIC_|import\.meta\.env\.VITE_)[A-Z0-9_]+)\s*[:=]\s*["'`](https?://[^"'`\s]+|/[^"'`\s]*)["'`]"""
)

# Source Map Comments & Inline Data URIs
SOURCEMAP_COMMENT_PATTERN = re.compile(
    r"""(?:/\*|//)[@#]\s+sourceMappingURL=(?P<url>[^\s*]+)(?:\s*\*\/)?""",
    re.MULTILINE
)

INLINE_SOURCEMAP_DATA_URI_PATTERN = re.compile(
    r"""^data:application/json(?:;charset=[^;]+)?;base64,(?P<b64>[A-Za-z0-9+/=]+)$"""
)

# Modern Frontend GraphQL Patterns
GRAPHQL_TEMPLATE_PATTERN = re.compile(
    r"""(?:(?:\b(?:gql|graphql)\s*`)|(?:/\*\s*GraphQL\s*\*/\s*[`"']))\s*(?:#graphql\s*)?(?P<query>(?P<type>query|mutation|subscription)\s+(?P<name>[a-zA-Z0-9_]+)?[^`"']*)""",
    re.IGNORECASE
)

GRAPHQL_AST_PATTERN = re.compile(
    r"""["']kind["']\s*:\s*["']OperationDefinition["']\s*,\s*["']operation["']\s*:\s*["'](?P<type>query|mutation|subscription)["']\s*,\s*["']name["']\s*:\s*\{[^}]*?["']value["']\s*:\s*["'](?P<name>[a-zA-Z0-9_]+)["']"""
)

# Endpoint Candidate Pattern
ENDPOINT_CANDIDATE_PATTERN = re.compile(
    r"""(?P<quote>["'`])(?P<endpoint>(?:https?://[a-zA-Z0-9\.\-_]+(?::\d+)?|/)(?:[a-zA-Z0-9_\-\.~%!$&'*+,;=:@]|/(?![/]))*)(?P=quote)"""
)

# False-Positive Filters
FP_SVG_PATH = re.compile(r"""^[MmLlHhVvCcSsQqTtAa\d\s,.-]{6,}$""")
FP_SVG_XMLNS = re.compile(r"""^https?://www\.w3\.org/(?:2000/svg|1999/xlink)$""")
FP_TAILWIND_FRACTION = re.compile(
    r"""^(?:-?(?:w|h|max-w|min-w|top|bottom|left|right|inset(?:-[xy])?|translate-[xy]|scale-[xy]|rotate|skew-[xy]|basis|col-span|row-span|grid-cols|grid-rows|aspect)-\d+/\d+|(?:bg|text|border|ring|divide|fill|stroke|from|to|via|placeholder|accent)-[a-z]+(?:-[a-z0-9]+)?/\d+)$""",
    re.IGNORECASE
)
FP_MIME_TYPE = re.compile(r"""^(?:application|audio|font|example|image|message|model|multipart|text|video)/[a-zA-Z0-9\.\+\-_]+$""", re.IGNORECASE)
FP_UUID = re.compile(r"""^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$""")
FP_DATE_FORMAT = re.compile(
    r"""^(?:\d{4}[/-](?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])|(?:YYYY|MM|DD)[/-](?:YYYY|MM|DD)[/-](?:YYYY|MM|DD))(?:[T\s][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?$""",
    re.IGNORECASE
)
FP_AST_TOKEN = re.compile(r"""^(?:Identifier|Literal|MemberExpression|CallExpression|BinaryExpression|UnaryExpression|BlockStatement|FunctionDeclaration|ReturnStatement)/[A-Za-z]+$""")
FP_BASE64_DATA = re.compile(r"""^[A-Za-z0-9+/]{32,}={0,2}$""")
```
