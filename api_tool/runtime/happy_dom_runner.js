/**
 * Headless DOM Runner powered by happy-dom.
 * Intercepts dynamic API calls (fetch / XMLHttpRequest), client-side routes (history.pushState/replaceState),
 * performs synthetic interaction passes, and extracts rendered DOM structures,
 * mutation links, forms, and Custom Elements.
 */

'use strict';

const { Window } = require('happy-dom');

const INTERACTION_SELECTOR = [
  'button:not([disabled])',
  'input[type="button"]:not([disabled])',
  'input[type="submit"]:not([disabled])',
  '[role="button"]:not([aria-disabled="true"])',
  '[role="tab"]',
  '[role="menuitem"]',
  'a[href="#"]',
  'a[href^="#/"]',
  'select:not([disabled])',
  'input[type="search"]:not([disabled])',
  'input[type="text"]:not([disabled])'
].join(', ');

/**
 * 32-bit FNV-1a hash algorithm.
 */
function fnv1a32(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16);
}

/**
 * Computes structural DOM skeleton string representing hierarchy and structural element types.
 */
function computeDOMSkeleton(node) {
  if (!node || node.nodeType !== 1) return '';

  const tag = node.tagName.toLowerCase();
  const role = node.getAttribute && node.getAttribute('role') ? `[role=${node.getAttribute('role')}]` : '';
  const type = node.getAttribute && node.getAttribute('type') ? `[type=${node.getAttribute('type')}]` : '';

  const children = node.children || [];
  const parts = [];
  for (let i = 0; i < children.length; i++) {
    const s = computeDOMSkeleton(children[i]);
    if (s) parts.push(s);
  }

  if (node.shadowRoot && node.shadowRoot.children) {
    const shadowParts = [];
    for (let i = 0; i < node.shadowRoot.children.length; i++) {
      const s = computeDOMSkeleton(node.shadowRoot.children[i]);
      if (s) shadowParts.push(s);
    }
    if (shadowParts.length > 0) {
      parts.push(`#shadow(${shadowParts.join(',')})`);
    }
  }

  const elKey = `${tag}${role}${type}`;
  return parts.length > 0 ? `${elKey}(${parts.join(',')})` : elKey;
}

/**
 * Recursively queries candidate interactables from both light and shadow DOM.
 */
function queryAllCandidates(root) {
  const candidates = [];
  function search(node) {
    if (!node) return;
    if (node.querySelectorAll) {
      try {
        const found = node.querySelectorAll(INTERACTION_SELECTOR);
        for (let i = 0; i < found.length; i++) {
          candidates.push(found[i]);
        }
      } catch (_) {}
    }
    const children = node.children || [];
    for (let i = 0; i < children.length; i++) {
      if (children[i].shadowRoot) {
        search(children[i].shadowRoot);
      }
    }
  }
  search(root);
  return candidates;
}

/**
 * Checks if an element should be treated as a button/link for synthetic interactions.
 */
function isButtonOrLink(el) {
  const tag = el.tagName ? el.tagName.toLowerCase() : '';
  const type = el.getAttribute ? (el.getAttribute('type') || '').toLowerCase() : '';
  if (tag === 'button' || tag === 'a') return true;
  if (tag === 'input' && (type === 'button' || type === 'submit' || type === 'reset' || type === 'image')) return true;
  const role = el.getAttribute ? (el.getAttribute('role') || '').toLowerCase() : '';
  if (role === 'button' || role === 'tab' || role === 'menuitem') return true;
  return false;
}

/**
 * Dispatches synthetic interaction events to a target element.
 */
function interactWithElement(el, window, testQuery = 'test') {
  if (isButtonOrLink(el)) {
    // For buttons/links: dispatch bubbling pointerdown, mousedown, click
    const pointerEvt = typeof window.PointerEvent === 'function'
      ? new window.PointerEvent('pointerdown', { bubbles: true, cancelable: true })
      : new window.Event('pointerdown', { bubbles: true, cancelable: true });
    el.dispatchEvent(pointerEvt);

    const mouseEvt = typeof window.MouseEvent === 'function'
      ? new window.MouseEvent('mousedown', { bubbles: true, cancelable: true })
      : new window.Event('mousedown', { bubbles: true, cancelable: true });
    el.dispatchEvent(mouseEvt);

    const clickEvt = typeof window.MouseEvent === 'function'
      ? new window.MouseEvent('click', { bubbles: true, cancelable: true })
      : new window.Event('click', { bubbles: true, cancelable: true });
    el.dispatchEvent(clickEvt);
  } else if (el.tagName && el.tagName.toLowerCase() === 'select') {
    if (el.options && el.options.length > 1) {
      el.selectedIndex = 1;
    }
    el.dispatchEvent(new window.Event('change', { bubbles: true, cancelable: true }));
  } else {
    // For inputs: dispatch input, change, keydown:Enter with test query
    try {
      el.value = testQuery;
    } catch (_) {}

    el.dispatchEvent(new window.Event('input', { bubbles: true, cancelable: true }));
    el.dispatchEvent(new window.Event('change', { bubbles: true, cancelable: true }));

    const keyEvt = typeof window.KeyboardEvent === 'function'
      ? new window.KeyboardEvent('keydown', {
          key: 'Enter',
          code: 'Enter',
          keyCode: 13,
          which: 13,
          bubbles: true,
          cancelable: true
        })
      : new window.Event('keydown', { bubbles: true, cancelable: true });
    el.dispatchEvent(keyEvt);
  }
}

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
 * Evaluates the given page payload and extracts dynamic endpoints, rendered HTML, links, forms, and routes.
 */
async function runHappyDOM(payload) {
  const url = payload.url || 'http://localhost';
  const html = payload.html || '';
  const scripts = Array.isArray(payload.scripts) ? payload.scripts : [];
  const interact = payload.interact !== false;
  const maxInteractions = typeof payload.max_interactions === 'number' ? payload.max_interactions : 30;

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

  // --- Discovered collections ---
  const discoveredLinks = [];
  const seenLinks = new Set();
  const mutationLinks = new Set();
  const forms = [];
  const seenForms = new Set();
  const customElements = new Set();

  function recordDiscoveredLink(linkUrl) {
    if (!linkUrl || typeof linkUrl !== 'string') return;
    const trimmed = linkUrl.trim();
    if (trimmed && !seenLinks.has(trimmed)) {
      seenLinks.add(trimmed);
      discoveredLinks.push(trimmed);
    }
  }

  function recordMutationLink(linkUrl) {
    if (!linkUrl || typeof linkUrl !== 'string') return;
    const trimmed = linkUrl.trim();
    if (trimmed) {
      mutationLinks.add(trimmed);
      recordDiscoveredLink(trimmed);
    }
  }

  // --- Intercept window.history.pushState and window.history.replaceState ---
  const pushedRoutes = [];
  const seenRoutes = new Set();

  function recordPushedRoute(routeUrl) {
    if (routeUrl === undefined || routeUrl === null) return;
    let strUrl = typeof routeUrl === 'string' ? routeUrl : String(routeUrl);
    strUrl = strUrl.trim();
    if (strUrl && !seenRoutes.has(strUrl)) {
      seenRoutes.add(strUrl);
      pushedRoutes.push(strUrl);
      recordDiscoveredLink(strUrl);
    }
  }

  if (window.history) {
    const origPushState = window.history.pushState ? window.history.pushState.bind(window.history) : null;
    window.history.pushState = function (state, unused, url) {
      if (url) recordPushedRoute(url);
      if (origPushState) {
        try {
          return origPushState(state, unused, url);
        } catch (_) {}
      }
    };

    const origReplaceState = window.history.replaceState ? window.history.replaceState.bind(window.history) : null;
    window.history.replaceState = function (state, unused, url) {
      if (url) recordPushedRoute(url);
      if (origReplaceState) {
        try {
          return origReplaceState(state, unused, url);
        } catch (_) {}
      }
    };
  }

  // Prevent default page navigation on submit events while allowing event handlers to fire
  window.addEventListener(
    'submit',
    (e) => {
      e.preventDefault();
    },
    true
  );

  // --- Ingest HTML ---
  if (html) {
    window.document.write(html);
  }

  // Ensure body element exists
  if (!window.document.body) {
    const b = window.document.createElement('body');
    if (window.document.documentElement) {
      window.document.documentElement.appendChild(b);
    }
  }

  function recordForm(formEl, isMutation = false) {
    if (!formEl || !formEl.tagName || formEl.tagName.toLowerCase() !== 'form') return;
    const action = formEl.getAttribute ? (formEl.getAttribute('action') || '') : '';
    const method = formEl.getAttribute ? ((formEl.getAttribute('method') || 'GET').toUpperCase()) : 'GET';
    const formObj = {
      action: action,
      method: method,
      inputs: []
    };
    const inputs = formEl.querySelectorAll
      ? formEl.querySelectorAll('input, select, textarea, button')
      : [];
    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      formObj.inputs.push({
        name: input.getAttribute('name') || '',
        type: input.getAttribute('type') || input.tagName.toLowerCase(),
        value: input.value || ''
      });
    }
    const formKey = `${formObj.method}:${formObj.action}:${formObj.inputs.map(i => i.name + '=' + i.type).join('&')}`;
    if (!seenForms.has(formKey)) {
      seenForms.add(formKey);
      forms.push(formObj);
    }
    if (action && action.trim()) {
      if (isMutation) {
        recordMutationLink(action.trim());
      } else {
        recordDiscoveredLink(action.trim());
      }
    }
  }

  function extractFromTree(node, isMutation = false) {
    if (!node || node.nodeType !== 1) return;

    const tag = node.tagName.toLowerCase();
    if (tag.includes('-')) {
      customElements.add(tag);
    }

    if (tag === 'a' && node.hasAttribute('href')) {
      const href = node.getAttribute('href');
      if (isMutation) {
        recordMutationLink(href);
      } else {
        recordDiscoveredLink(href);
      }
    }

    if (node.hasAttribute('data-url')) {
      const dataUrl = node.getAttribute('data-url');
      if (isMutation) {
        recordMutationLink(dataUrl);
      } else {
        recordDiscoveredLink(dataUrl);
      }
    }

    if (tag === 'form') {
      recordForm(node, isMutation);
    }

    if (node.querySelectorAll) {
      try {
        const links = node.querySelectorAll('a[href], [data-url]');
        for (let i = 0; i < links.length; i++) {
          const el = links[i];
          if (el.hasAttribute('href')) {
            const h = el.getAttribute('href');
            if (isMutation) recordMutationLink(h); else recordDiscoveredLink(h);
          }
          if (el.hasAttribute('data-url')) {
            const d = el.getAttribute('data-url');
            if (isMutation) recordMutationLink(d); else recordDiscoveredLink(d);
          }
        }
        const childForms = node.querySelectorAll('form');
        for (let i = 0; i < childForms.length; i++) {
          recordForm(childForms[i], isMutation);
        }
      } catch (_) {}
    }

    if (node.shadowRoot) {
      extractFromTree(node.shadowRoot, isMutation);
    }
  }

  function processMutationRecords(records) {
    if (!records || !records.length) return;
    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      if (record.type === 'childList') {
        const addedNodes = record.addedNodes || [];
        for (let j = 0; j < addedNodes.length; j++) {
          extractFromTree(addedNodes[j], true);
        }
      } else if (record.type === 'attributes') {
        const target = record.target;
        if (target && target.getAttribute) {
          const attr = record.attributeName;
          const val = target.getAttribute(attr);
          if (val) {
            recordMutationLink(val);
          }
          if (attr === 'action' && target.tagName && target.tagName.toLowerCase() === 'form') {
            recordForm(target, true);
          }
        }
      }
    }
  }

  // --- Add MutationObserver on document.body ---
  let observer = null;
  if (window.MutationObserver && window.document.body) {
    observer = new window.MutationObserver((records) => {
      processMutationRecords(records);
    });
    observer.observe(window.document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['href', 'action', 'data-url']
    });
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

  // --- Await initial asynchronous operations up to grace limit ---
  try {
    await Promise.race([
      window.happyDOM.waitUntilComplete(),
      new Promise(resolve => setTimeout(resolve, 2000))
    ]);
  } catch (_) {}

  // Flush any mutation records from initial script execution
  if (observer) {
    try {
      processMutationRecords(observer.takeRecords());
    } catch (_) {}
  }

  // --- Synthetic Interaction Pass ---
  if (interact && window.document.body) {
    const seenSkeletonHashes = new Set();
    const initialSkeleton = computeDOMSkeleton(window.document.body);
    seenSkeletonHashes.add(fnv1a32(initialSkeleton));

    const candidateQueue = queryAllCandidates(window.document.body);
    const interactedElements = new Set();
    let interactionCount = 0;

    while (candidateQueue.length > 0 && interactionCount < maxInteractions) {
      const el = candidateQueue.shift();
      if (!el || interactedElements.has(el)) continue;

      if (!el.isConnected) continue;
      if (el.hasAttribute && (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true')) {
        continue;
      }

      interactedElements.add(el);
      interactionCount++;

      try {
        interactWithElement(el, window, 'test');
      } catch (_) {}

      // Immediately after each interaction, call observer.takeRecords() (0ms synchronous retrieval)
      if (observer) {
        try {
          const records = observer.takeRecords();
          processMutationRecords(records);
        } catch (_) {}
      }

      // Check DOM skeleton hash; skip redundant states
      const currentSkeleton = computeDOMSkeleton(window.document.body);
      const currentHash = fnv1a32(currentSkeleton);

      if (!seenSkeletonHashes.has(currentHash)) {
        seenSkeletonHashes.add(currentHash);
        // Discover newly mounted candidate interactables from modals/drawers
        const newCandidates = queryAllCandidates(window.document.body);
        for (let i = 0; i < newCandidates.length; i++) {
          const cand = newCandidates[i];
          if (!interactedElements.has(cand) && !candidateQueue.includes(cand)) {
            candidateQueue.push(cand);
          }
        }
      }
    }
  }

  // Final flush and disconnect observer
  if (observer) {
    try {
      processMutationRecords(observer.takeRecords());
      observer.disconnect();
    } catch (_) {}
  }

  // Await any pending promises/tasks
  try {
    await Promise.race([
      window.happyDOM.waitUntilComplete(),
      new Promise(resolve => setTimeout(resolve, 500))
    ]);
  } catch (_) {}

  // --- Walk full DOM to extract rendered links, forms, and custom elements ---
  function walk(node) {
    if (!node) return;

    if (node.tagName) {
      const tag = node.tagName.toLowerCase();
      if (tag.includes('-')) {
        customElements.add(tag);
      }
      if (tag === 'a' && node.hasAttribute('href')) {
        const href = node.getAttribute('href');
        recordDiscoveredLink(href);
      }
      if (node.hasAttribute('data-url')) {
        const dataUrl = node.getAttribute('data-url');
        recordDiscoveredLink(dataUrl);
      }
      if (tag === 'form') {
        recordForm(node, false);
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
    mutation_links: Array.from(mutationLinks),
    pushed_routes: pushedRoutes,
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
