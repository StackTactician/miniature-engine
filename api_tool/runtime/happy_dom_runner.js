/**
 * Headless DOM Runner powered by happy-dom.
 * Intercepts dynamic API calls (fetch / XMLHttpRequest) and extracts rendered DOM structures,
 * discovered links, forms, and Shadow DOM / Custom Elements.
 */

'use strict';

const { Window } = require('happy-dom');

/**
 * Normalizes HTTP headers from various formats into a plain object.
 */
function extractHeaders(headers) {
  if (!headers) return {};
  const result = {};
  if (typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }
  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      if (key !== undefined) {
        result[String(key)] = String(value);
      }
    }
    return result;
  }
  if (typeof headers === 'object') {
    for (const [key, value] of Object.entries(headers)) {
      result[key] = String(value);
    }
    return result;
  }
  return {};
}

/**
 * Normalizes request body to string or null.
 */
function extractBody(body) {
  if (body === undefined || body === null) return null;
  if (typeof body === 'string') return body;
  try {
    return JSON.stringify(body);
  } catch (_) {
    return String(body);
  }
}

/**
 * Evaluates the given page payload and extracts dynamic endpoints, rendered HTML, and links.
 */
async function runHappyDOM(payload) {
  const url = payload.url || 'http://localhost';
  const html = payload.html || '';
  const scripts = Array.isArray(payload.scripts) ? payload.scripts : [];

  const window = new Window({
    url: url,
    settings: {
      disableJavaScriptEvaluation: false,
      enableJavaScriptEvaluation: true,
      disableJavaScriptFileLoading: true,
      suppressInsecureJavaScriptEnvironmentWarning: true
    }
  });

  const dynamicEndpoints = [];
  const seenDynamicCalls = new Set();

  function recordDynamicCall(endpoint) {
    const key = `${endpoint.type}:${endpoint.method}:${endpoint.url}:${endpoint.body || ''}`;
    if (!seenDynamicCalls.has(key)) {
      seenDynamicCalls.add(key);
      dynamicEndpoints.push(endpoint);
    }
  }

  // --- Monkey-patch window.fetch ---
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    let callUrl = '';
    let method = 'GET';
    let headers = {};
    let body = null;

    if (typeof input === 'string') {
      callUrl = input;
    } else if (input && typeof input === 'object') {
      if (input.url) callUrl = input.url;
      if (input.method) method = input.method.toUpperCase();
      if (input.headers) headers = extractHeaders(input.headers);
    } else {
      callUrl = String(input);
    }

    if (init && typeof init === 'object') {
      if (init.method) method = init.method.toUpperCase();
      if (init.headers) Object.assign(headers, extractHeaders(init.headers));
      if (init.body !== undefined && init.body !== null) {
        body = extractBody(init.body);
      }
    }

    recordDynamicCall({
      url: callUrl,
      method: method,
      headers: headers,
      body: body,
      type: 'fetch'
    });

    // Provide a mocked Response so client promises continue cleanly
    return new window.Response(
      JSON.stringify({ ok: true, mocked: true, endpoint: callUrl }),
      {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' }
      }
    );
  };

  // --- Monkey-patch window.XMLHttpRequest ---
  const OriginalXHR = window.XMLHttpRequest;
  function PatchedXMLHttpRequest() {
    const xhr = new OriginalXHR();
    let xhrMethod = 'GET';
    let xhrUrl = '';
    const xhrHeaders = {};

    const origOpen = xhr.open ? xhr.open.bind(xhr) : null;
    xhr.open = function (m, u) {
      xhrMethod = (m || 'GET').toUpperCase();
      xhrUrl = u ? String(u) : '';
      if (origOpen) {
        try {
          return origOpen.apply(xhr, arguments);
        } catch (_) {}
      }
    };

    const origSetHeader = xhr.setRequestHeader ? xhr.setRequestHeader.bind(xhr) : null;
    xhr.setRequestHeader = function (header, value) {
      if (header) {
        xhrHeaders[header] = String(value);
      }
      if (origSetHeader) {
        try {
          return origSetHeader.apply(xhr, arguments);
        } catch (_) {}
      }
    };

    const origSend = xhr.send ? xhr.send.bind(xhr) : null;
    xhr.send = function (b) {
      const xhrBody = extractBody(b);
      recordDynamicCall({
        url: xhrUrl,
        method: xhrMethod,
        headers: { ...xhrHeaders },
        body: xhrBody,
        type: 'xhr'
      });

      // Simulate async completion so XHR handlers resolve without hanging
      setTimeout(() => {
        try {
          Object.defineProperty(xhr, 'readyState', { value: 4, configurable: true });
          Object.defineProperty(xhr, 'status', { value: 200, configurable: true });
          Object.defineProperty(xhr, 'statusText', { value: 'OK', configurable: true });
          Object.defineProperty(xhr, 'responseText', {
            value: JSON.stringify({ ok: true, mocked: true, endpoint: xhrUrl }),
            configurable: true
          });
          Object.defineProperty(xhr, 'response', {
            value: JSON.stringify({ ok: true, mocked: true, endpoint: xhrUrl }),
            configurable: true
          });

          if (typeof xhr.onreadystatechange === 'function') {
            xhr.onreadystatechange();
          }
          if (typeof xhr.onload === 'function') {
            xhr.onload();
          }
          if (typeof xhr.onloadend === 'function') {
            xhr.onloadend();
          }
          xhr.dispatchEvent(new window.Event('readystatechange'));
          xhr.dispatchEvent(new window.Event('load'));
          xhr.dispatchEvent(new window.Event('loadend'));
        } catch (_) {}
      }, 5);

      if (origSend) {
        try {
          return origSend.apply(xhr, arguments);
        } catch (_) {}
      }
    };

    return xhr;
  }

  PatchedXMLHttpRequest.prototype = OriginalXHR.prototype;
  Object.assign(PatchedXMLHttpRequest, OriginalXHR);
  window.XMLHttpRequest = PatchedXMLHttpRequest;

  // --- Ingest HTML & evaluate inline scripts ---
  if (html) {
    window.document.write(html);
  }

  // --- Evaluate additional scripts if provided ---
  for (const scriptCode of scripts) {
    if (typeof scriptCode === 'string' && scriptCode.trim()) {
      try {
        window.eval(scriptCode);
      } catch (err) {
        // Script error recorded or ignored to ensure runner resilience
      }
    }
  }

  // --- Dispatch lifecycle events ---
  try {
    window.document.dispatchEvent(
      new window.Event('DOMContentLoaded', { bubbles: true, cancelable: true })
    );
  } catch (_) {}

  try {
    window.dispatchEvent(new window.Event('load'));
  } catch (_) {}

  // --- Await asynchronous operations up to grace limit ---
  try {
    await Promise.race([
      window.happyDOM.waitUntilComplete(),
      new Promise(resolve => setTimeout(resolve, 2000))
    ]);
  } catch (_) {}

  // --- Extract rendered DOM links, forms, and custom elements / shadow roots ---
  const discoveredLinks = [];
  const seenLinks = new Set();
  const forms = [];
  const customElements = new Set();

  function walk(node) {
    if (!node) return;

    if (node.tagName) {
      const tag = node.tagName.toLowerCase();
      if (tag.includes('-')) {
        customElements.add(tag);
      }
      if (tag === 'a' && node.hasAttribute('href')) {
        const href = node.getAttribute('href');
        if (href && href.trim()) {
          const trimmed = href.trim();
          if (!seenLinks.has(trimmed)) {
            seenLinks.add(trimmed);
            discoveredLinks.push(trimmed);
          }
        }
      }
      if (tag === 'form') {
        const formObj = {
          action: node.getAttribute('action') || '',
          method: (node.getAttribute('method') || 'GET').toUpperCase(),
          inputs: []
        };
        const inputs = node.querySelectorAll
          ? node.querySelectorAll('input, select, textarea, button')
          : [];
        for (const input of inputs) {
          formObj.inputs.push({
            name: input.getAttribute('name') || '',
            type: input.getAttribute('type') || input.tagName.toLowerCase(),
            value: input.value || ''
          });
        }
        forms.push(formObj);
      }
    }

    // Traverse Shadow Root if present
    if (node.shadowRoot) {
      walk(node.shadowRoot);
    }

    // Traverse Template content if present
    if (node.content && node.content.children) {
      walk(node.content);
    }

    // Traverse Child Nodes
    const children = node.children || [];
    for (let i = 0; i < children.length; i++) {
      walk(children[i]);
    }
  }

  if (window.document.documentElement) {
    walk(window.document.documentElement);
  }

  const renderedHtml = window.document.documentElement
    ? window.document.documentElement.outerHTML
    : '';

  // Clean up
  try {
    window.close();
  } catch (_) {}

  return {
    rendered_html: renderedHtml,
    dynamic_endpoints: dynamicEndpoints,
    discovered_links: discoveredLinks,
    forms: forms,
    custom_elements: Array.from(customElements)
  };
}

// --- Main execution reading from stdin ---
function main() {
  const chunks = [];
  process.stdin.on('data', chunk => chunks.push(chunk));
  process.stdin.on('end', async () => {
    try {
      const rawInput = Buffer.concat(chunks).toString('utf8');
      const payload = rawInput.trim() ? JSON.parse(rawInput) : {};
      const result = await runHappyDOM(payload);
      const jsonStr = JSON.stringify(result);
      if (!process.stdout.write(jsonStr)) {
        process.stdout.once('drain', () => {
          process.exit(0);
        });
      } else {
        process.stdout.write('', () => {
          process.exit(0);
        });
      }
    } catch (err) {
      const errStr = err ? (err.stack || String(err)) : 'Unknown error';
      if (!process.stderr.write(errStr)) {
        process.stderr.once('drain', () => {
          process.exit(1);
        });
      } else {
        process.stderr.write('', () => {
          process.exit(1);
        });
      }
    }
  });
}

main();
