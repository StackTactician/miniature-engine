const JSON_MIMES = new Set(['application/json', 'text/json'])

function isJson(mimeType = '') {
  return JSON_MIMES.has(mimeType.split(';')[0].trim().toLowerCase())
}

function headersToObject(headers = []) {
  return Object.fromEntries(headers.map((h) => [h.name.toLowerCase(), h.value]))
}

function parseJsonSafe(text) {
  if (!text) return null
  try { return JSON.parse(text) } catch { return null }
}

export function parseHar(har) {
  const entries = har?.log?.entries ?? []
  return entries
    .filter((e) => isJson(e.response?.content?.mimeType))
    .map((e) => ({
      method: e.request.method.toUpperCase(),
      url: e.request.url,
      request_headers: headersToObject(e.request.headers),
      request_body: parseJsonSafe(e.request.postData?.text),
      response_status: e.response.status,
      response_headers: headersToObject(e.response.headers),
      response_body: parseJsonSafe(e.response.content?.text),
    }))
}
