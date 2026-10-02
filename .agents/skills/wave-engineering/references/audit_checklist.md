# Security Audit & Stress Benchmark Checklist

This checklist must be executed during **Phase 3 (Wave 2)** by independent Auditor and Stress Tester subagents.

---

## 1. Security Vulnerability Checklist

### SSRF (Server-Side Request Forgery)
- [ ] **Scheme Enforcement**: Allow only `http` and `https`. Reject `file:`, `gopher:`, `ftp:`, `javascript:`, etc.
- [ ] **DNS & IP Resolution**: Resolve hostname using `socket.getaddrinfo(host, None)`.
- [ ] **Private IP Ranges**: Block RFC 1918 subnets:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- [ ] **Loopback & Localhost**: Block `127.0.0.0/8`, `::1`, and `localhost`.
- [ ] **Link-Local & Multicast**: Block `169.254.0.0/16`, `fe80::/10`, `224.0.0.0/4`.
- [ ] **Cloud Metadata Services**: Block `169.254.169.254`, `metadata.google.internal`, AWS/GCP/Azure instance metadata endpoints.
- [ ] **Alternative Encodings**: Test and block:
  - Decimal IP format (e.g., `2130706433` -> `127.0.0.1`)
  - Hex IP format (e.g., `0x7f000001`)
  - Octal IP format (e.g., `0177.0.0.1`)
  - IPv4-mapped IPv6 (e.g., `::ffff:127.0.0.1`, `::ffff:a00:1`)

### Path Traversal & File Output
- [ ] **Basename Sanitization**: When saving exports or unpacking files, strip path traversal prefixes using `os.path.basename(filename)`.
- [ ] **Commonpath Verification**: Ensure resolved destination is strictly within the target root directory:
  ```python
  full_path = os.path.realpath(os.path.join(dest_dir, relative_path))
  if os.path.commonpath([dest_dir, full_path]) != dest_dir:
      raise ValueError("Path traversal attempt detected")
  ```
- [ ] **Null Byte Injection**: Reject file paths containing `\x00`.
- [ ] **Adversarial Prefix Tests**: Verify resistance against `../../../../etc/passwd`, `C:\Windows\System32`, `\\unc\share`, `....//`.

### Recursion & Stack Safety
- [ ] **Depth Limiting**: Any function traversing nested structures (dicts, ASTs, JSON schemas, serializers) must accept a `max_depth` parameter (default `30` or `50`).
- [ ] **Circular Reference Guard**: Maintain a `seen: Set[int]` of visited object IDs to safely break cycles without raising `RecursionError`.

### Concurrency & Leaks
- [ ] **Semaphore Safety**: Ensure semaphore acquisition uses `try: ... finally: sem.release()` or `async with sem:`.
- [ ] **HTTP Client Lifetime**: Always run HTTP clients in `async with httpx.AsyncClient() as client:`.

---

## 2. Stress & Performance Testing Checklist

### ReDoS (Linear Time $O(N)$)
- [ ] Construct adversarial strings: 100,000+ characters of repeating quotes, brackets, slashes, or template literals.
- [ ] Measure regex execution time.
- [ ] **Pass Criterion**: Regex evaluation must complete in **< 50ms**.

### Memory Benchmark (`tracemalloc`)
- [ ] Setup `tracemalloc` measurement before generating/processing high-volume data:
  ```python
  import tracemalloc
  tracemalloc.start()
  # Execute high-volume operation (e.g., 2,000 items)
  current, peak = tracemalloc.get_traced_memory()
  tracemalloc.stop()
  peak_mb = peak / (1024 * 1024)
  self.assertLess(peak_mb, 10.0, f"Peak RAM delta {peak_mb:.2f}MB exceeded 10MB limit")
  ```
- [ ] **Pass Criterion**: Peak RAM delta strictly **< 10.0MB** for 2,000 items.

### High-Volume Throughput
- [ ] Generate 1,000–2,000 synthetic endpoints / operations.
- [ ] Benchmark export / parsing throughput.
- [ ] **Pass Criterion**: Sustained throughput of > 1,000 ops/second on mobile/ARM CPU.

### Resilience & Fault Injection
- [ ] Mock HTTP 429 Too Many Requests with `Retry-After: 1`. Assert graceful backoff.
- [ ] Mock SSL errors, connection timeouts, and EOF mid-stream. Assert clean exception handling without hanging.
