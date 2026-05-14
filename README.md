# tiny-s3-proxy

A caching S3 reverse proxy. Tiny as in footprint, not as in complexity.

## What it does

Sits between your application and an S3-compatible backend (R2, MinIO, etc.) and does three things well:

1. **Caches GET responses on disk** for configured prefixes, so repeated reads never hit the backend.
2. **Coalesces concurrent cache misses** — if 20 workers request the same uncached object simultaneously, one request hits the backend. The rest wait and read from the freshly-filled cache.
3. **Serves stale on transient backend failure** — if the backend returns a 5xx error or times out and there's a cached copy, you get data instead of an error. Semantic errors like 404 or 403 are not masked by stale data.

Everything else (PUT, DELETE, LIST, multipart, any S3 operation the proxy doesn't explicitly handle) passes through to the backend with re-signing and retries.

## Why it exists

When multiple workers or services share immutable artifacts through S3-compatible object storage, cold starts and transient backend failures produce a thundering herd of identical GETs against the same keys. This proxy absorbs that.

## How it works

The proxy classifies every inbound request into a typed S3 operation:

```
GET /bucket/key                          → GetObject (cached)
HEAD /bucket/key                         → HeadObject
PUT /bucket/key                          → PutObject → purge cache
DELETE /bucket/key                       → DeleteObject → purge cache
GET /bucket?list-type=2&...              → ListObjectsV2 (passthrough)
POST /bucket/key?uploads                 → CreateMultipartUpload
PUT /bucket/key?partNumber=N&uploadId=U  → UploadPart
POST /bucket/key?uploadId=U              → CompleteMultipartUpload → purge cache
DELETE /bucket/key?uploadId=U            → AbortMultipartUpload
anything else                            → raw passthrough with SigV4 re-signing
```

Requests are also routed through raw passthrough when they carry headers or query parameters the typed path cannot forward:

- **GET/HEAD** with `Range`, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, SSE-C headers, `x-amz-request-payer`, `x-amz-expected-bucket-owner`, or malformed/duplicate/unparseable `x-amz-checksum-mode`
- **GET/HEAD** with `?versionId`, `?partNumber`, or response-override query parameters
- **PUT** with `x-amz-copy-source` (CopyObject / UploadPartCopy)
- **PUT/DELETE/multipart** with operation-modifying `x-amz-*` headers not handled by the typed path (storage class, SSE, governance bypass, MFA, etc.)
- **GET** `?uploadId` (ListParts), **GET** `?uploads` (ListMultipartUploads), and incomplete multipart query combinations

GET responses for prefixes listed in `CACHEABLE_PREFIXES` are streamed to disk and to the client simultaneously. The default prefix list is empty, so GETs bypass the cache until `CACHEABLE_PREFIXES` is set. Cache hits stream directly from disk — the proxy never buffers a full object in memory for reads.

Writes (PUT, DELETE, multipart completion) purge the cache for the affected key immediately. If the on-disk purge fails, a durable poison marker is written so subsequent reads bypass the stale entry until it is cleaned up.

The proxy preserves the full set of standard S3 response headers through both fresh and cached paths, including `Content-Encoding`, `Cache-Control`, `Content-Disposition`, `Content-Language`, version IDs, SSE state, and other metadata; checksum headers are preserved only when the request carries `x-amz-checksum-mode: ENABLED`. HEAD-only headers are learned from a typed `HEAD` response before plain cached `HEAD` hits are served, so GET-warmed entries may do one backend `HEAD` to enrich the cache before those headers become cache hits. Checksum-mode GET and HEAD warm-up are tracked independently: a checksum-mode HEAD does not satisfy later checksum-mode GET hits (and vice versa), because the two methods can return different checksum surfaces on some S3-compatible backends. Write paths forward `Content-Encoding`, `Content-Disposition`, `Content-Language`, `Cache-Control`, and `Expires` to the backend alongside user metadata.

## Quick start

```bash
# Required
export FRONTEND_BUCKET=my-bucket
export BACKEND_ENDPOINT=https://xxx.r2.cloudflarestorage.com
export BACKEND_BUCKET=my-bucket
export BACKEND_ACCESS_KEY_ID=your-key
export BACKEND_SECRET_ACCESS_KEY=your-secret

# Cache opt-in: choose prefixes that are safe for your workload.
# Example for immutable artifact keys:
export CACHEABLE_PREFIXES=script_bundle/,bun_bundle/,tar/

# Run
cargo run --release
```

Or with Docker:

```bash
docker run -p 8080:8080 -p 9090:9090 \
  -v /data/cache:/cache \
  -e FRONTEND_BUCKET=my-bucket \
  -e BACKEND_ENDPOINT=https://xxx.r2.cloudflarestorage.com \
  -e BACKEND_BUCKET=my-bucket \
  -e BACKEND_ACCESS_KEY_ID=your-key \
  -e BACKEND_SECRET_ACCESS_KEY=your-secret \
  -e CACHEABLE_PREFIXES=script_bundle/,bun_bundle/,tar/ \
  ghcr.io/invakid404/tiny-s3-proxy:latest
```

Point your application at `http://localhost:8080` with path-style S3 addressing.

## Configuration

All configuration is via environment variables.

### Frontend

| Variable | Default | Description |
|---|---|---|
| `S3_LISTEN_ADDR` | `0.0.0.0:8080` | S3 API listen address |
| `ADMIN_LISTEN_ADDR` | `0.0.0.0:9090` | Admin/metrics listen address |
| `FRONTEND_BUCKET` | *required* | Bucket name clients use |
| `AUTH_MODE` | `trusted_internal` | Access control mode: `trusted_internal` (allow all) or `access_key_allowlist` (check access-key ID against allowlist — does NOT verify SigV4 signatures) |
| `ALLOWED_FRONTEND_KEYS` | | Comma-separated access key IDs for allowlist mode. NOTE: only the key ID is checked, not the signature — see security section below |
| `INBOUND_AUTH_VERIFY_SIGNATURES` | `false` | Opt-in strict SigV4 verification for inbound requests. Replaces the `AUTH_MODE` gate. See "Strict inbound SigV4 verification" below |
| `INBOUND_CREDENTIALS_PATH` | | Path to a JSON file with the inbound access-key id / secret pairs (v1) or STS-capable tuples (v2 — see "Strict inbound SigV4 verification" below). Required when `INBOUND_AUTH_VERIFY_SIGNATURES=true`; the file is loaded once at startup and a missing or malformed file fails the rollout |
| `INBOUND_AUTH_MAX_SKEW_SECS` | `900` | Maximum permitted clock skew (seconds) between the request `x-amz-date` and the proxy's wall clock in strict mode. Requests outside the window return `RequestTimeTooSkewed` |

### Backend

| Variable | Default | Description |
|---|---|---|
| `BACKEND_ENDPOINT` | *required* | S3-compatible endpoint URL. Must not embed credentials as URL userinfo — use `BACKEND_ACCESS_KEY_ID` and `BACKEND_SECRET_ACCESS_KEY` instead. Rejected at startup if userinfo is present |
| `BACKEND_REGION` | `auto` | AWS region |
| `BACKEND_BUCKET` | *required* | Actual backend bucket name |
| `BACKEND_ACCESS_KEY_ID` | *required* | Backend credentials |
| `BACKEND_SECRET_ACCESS_KEY` | *required* | Backend credentials |
| `BACKEND_USE_PATH_STYLE` | `true` | Use path-style S3 addressing. When `false`, the typed SDK path uses virtual-hosted-style and passthrough rewrites URLs to `bucket.endpoint/key` format |
| `BACKEND_ALLOW_HTTP` | `false` | Allow plaintext HTTP to backend. Rejected at startup if endpoint is `http://` and this is not set |

### Cache

| Variable | Default | Description |
|---|---|---|
| `CACHE_DIR` | `/cache` | Disk cache directory. Must not be shared across processes — startup acquires an exclusive advisory lock on `<CACHE_DIR>/.lock` and a second instance against the same path fails fast |
| `CACHE_MAX_BYTES` | `10737418240` (10 GB) | Maximum cache size on disk |
| `CACHE_MAX_OBJECT_BYTES` | `536870912` (512 MB) | Maximum single object size to cache. Objects with unknown `Content-Length` are not cached |
| `CACHEABLE_PREFIXES` | *(empty)* | Comma-separated object key prefixes to cache. Empty/unset means all GETs bypass the cache. Example: `script_bundle/,bun_bundle/,tar/` |
| `CACHE_SERVE_STALE_ON_ERROR` | `true` | Serve stale cache entries on transient backend errors (5xx, timeouts). Semantic errors like 404/403 are never masked |
| `CACHE_EVICTION_INTERVAL_SECS` | `300` | Seconds between LRU eviction passes |

### Request Limits

| Variable | Default | Description |
|---|---|---|
| `MAX_REQUEST_BODY_BYTES` | `268435456` (256 MiB) | Maximum request body size for PUT, UploadPart, and passthrough. Returns `EntityTooLarge` if exceeded. Each in-flight upload buffers this much memory (retry uses O(1) `Bytes::clone`, not a data copy) |

### Retry

| Variable | Default | Description |
|---|---|---|
| `GET_MAX_ATTEMPTS` | `3` | Retry attempts for GET (typed and passthrough) |
| `HEAD_MAX_ATTEMPTS` | `3` | Retry attempts for HEAD (typed and passthrough) |
| `LIST_MAX_ATTEMPTS` | `3` | Retry attempts for LIST |
| `PUT_MAX_ATTEMPTS` | `1` | Retry attempts for PUT |
| `DELETE_MAX_ATTEMPTS` | `2` | Retry attempts for DELETE (typed and passthrough) |
| `RETRY_BASE_BACKOFF_MS` | `100` | Base backoff for exponential retry (applies to both typed and passthrough paths) |
| `UPSTREAM_CONNECT_TIMEOUT_MS` | `5000` | Backend connect timeout |
| `UPSTREAM_REQUEST_TIMEOUT_MS` | `30000` | Backend read-idle timeout (typed path uses this as request timeout; passthrough uses it as read timeout so streaming is not cut off) |

## Security

### Access control modes

`tiny-s3-proxy` supports two access control modes via `AUTH_MODE`:

- **`trusted_internal`** (default): All requests are accepted. Use this when the proxy is behind a VPC, service mesh, or other network boundary that already authenticates callers.

- **`access_key_allowlist`**: Requests must include a valid SigV4 `Authorization` header (`AWS4-HMAC-SHA256 Credential=AKID/...`) with an access key ID present in `ALLOWED_FRONTEND_KEYS`. **The proxy does NOT verify the SigV4 signature, request hash, date, or signed headers.** It validates the scheme and field structure but not the cryptographic MAC. This mode provides coarse-grained access control — not cryptographic authentication. It exists as a lightweight gate for multi-tenant internal environments where network isolation is the primary security boundary.

In both modes, the proxy re-signs all backend requests with its own `BACKEND_ACCESS_KEY_ID` / `BACKEND_SECRET_ACCESS_KEY`. Inbound signatures are never validated against client secrets. Client-side auth/signing headers (`x-amz-security-token`, `x-amz-credential`, `x-amz-signature`, etc.) are stripped before forwarding to the backend.

If you need actual signature verification with per-client secrets, set `INBOUND_AUTH_VERIFY_SIGNATURES=true` (see below) or place the proxy behind an authenticating reverse proxy.

### Strict inbound SigV4 verification

`INBOUND_AUTH_VERIFY_SIGNATURES=true` enables cryptographic SigV4 verification of inbound requests. When this flag is set, the legacy `AUTH_MODE` gate is bypassed entirely — every normal (non-streaming) request must carry a valid `AWS4-HMAC-SHA256` `Authorization` header (or presigned `X-Amz-*` query parameters) signed with a credential listed in `INBOUND_CREDENTIALS_PATH`, and signed payloads must match the actual body bytes.

The credentials file is a versioned JSON document. Both **v1** (long-lived credentials only) and **v2** (long-lived + STS-issued temporary credentials) are supported:

```json
{
  "version": 1,
  "credentials": [
    { "access_key_id": "AKID-FRONTEND-1", "secret_access_key": "..." },
    { "access_key_id": "AKID-FRONTEND-2", "secret_access_key": "..." }
  ]
}
```

```json
{
  "version": 2,
  "credentials": [
    {
      "access_key_id": "AKID-LONG",
      "secret_access_key": "long-lived-secret"
    },
    {
      "access_key_id": "ASIA-TEMP",
      "secret_access_key": "temporary-secret",
      "session_token": "FQoGZXIvYXdzE...",
      "expires_at": "2026-05-14T18:30:00Z"
    }
  ]
}
```

- `version` must be `1` or `2`. Unknown fields and unknown top-level keys are rejected at load time (typos fail the rollout).
- Both `access_key_id` and `secret_access_key` must be non-empty and free of leading/trailing whitespace.
- v1 files must not carry `session_token` or `expires_at`; use v2 if you need STS support.
- In v2, the logical credential identity is `(access_key_id, session_token)` — a request without a token never matches a token-bearing entry, and vice versa. Sharing one access-key id across a long-lived and a token-bearing entry is allowed because they occupy disjoint namespaces.
- `session_token`, when present, must be non-empty. The proxy treats the token as an opaque byte string (no `+` → space translation, no case folding) and compares with `subtle::ConstantTimeEq`.
- `expires_at` (RFC 3339) is **required** when `session_token` is set; it is **optional** on no-token entries and, when present, is enforced (useful for planned key retirement).
- Duplicate `(access_key_id, session_token)` tuples are rejected without echoing the token value in the validation error.
- Secrets and session tokens are zeroized in memory on the final drop (`Zeroizing<String>` behind an `Arc`); the raw file contents are wiped immediately after parsing.

Strict-mode behavior:

| Inbound flow | Strict-mode behavior |
|---|---|
| Normal signed requests (`UNSIGNED-PAYLOAD`, signed SHA-256) | Verified end-to-end (header, scope, date, canonical request, body hash if signed) |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | Verified for the request header; chunk framing handled by the existing decoder |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD*` (signed aws-chunked) | Verified chunk-by-chunk (PR 2 of #63) |
| Presigned URLs (`X-Amz-Signature` query parameter) | Verified including validity window and canonical query (PR 3 of #63) |
| STS / temporary credentials (`x-amz-security-token`, `X-Amz-Security-Token`) | Verified against v2 token-bearing entries (PR 4 of #63) |
| `AWS4-ECDSA-P256-SHA256` (SigV4A) header auth | Verified — P-256 verifying key derived from `(access_key_id, secret_access_key)` via the AWS SP 800-108 KDF; signature is DER-hex (≤144 chars); `x-amz-region-set` must be present and signed (PR 5 of #63) |
| SigV4A presigned URLs (`X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256`) | Verified — same KDF + ECDSA verify; `X-Amz-Region-Set` required as a canonical query parameter (PR 5 of #63) |
| `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*` (ECDSA-signed aws-chunked) | Verified chunk-by-chunk; AWS CRT's `*`-to-144 padding on `chunk-signature=` is stripped before hex decode and chain advancement (PR 5 of #63) |

STS-specific error mapping (PR 4 of #63):

| Condition | Error |
|---|---|
| `(access_key_id, session_token)` matches but the entry's `expires_at` is in the past | `ExpiredToken` 400 |
| Access key not configured, or tuple miss in either namespace | `InvalidAccessKeyId` 403 |
| Header-auth: `x-amz-security-token` header present but not in `SignedHeaders` | `AuthorizationHeaderMalformed` 400 |
| Duplicate `x-amz-security-token` header or duplicate `X-Amz-Security-Token` query parameter | `AuthorizationHeaderMalformed` 400 |
| Empty token value (header or query) | `AuthorizationHeaderMalformed` 400 |

SigV4A-specific notes (PR 5 of #63):

- The credential scope is regionless: `<akid>/<yyyymmdd>/s3/aws4_request`. Five-component HMAC-shaped credentials are rejected as `AuthorizationHeaderMalformed`.
- `x-amz-region-set` (header auth) / `X-Amz-Region-Set` (presigned) is required and is part of the signed canonical request. The proxy forwards this value without filtering — multi-region region sets (e.g. `us-west-*`) are accepted because the proxy re-signs outbound backend requests with the configured `BACKEND_REGION` regardless.
- Chunk and trailer signatures on `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*` uploads are lowercase hex of DER ECDSA signatures (variable length, max 144 chars), optionally right-padded with `*` to that width per AWS CRT's wire format. Padding is stripped before hex decode and before chain advancement.
- The derived P-256 verifying key is the only key material kept on the per-request `VerifiedRequest`; the private scalar is built, used to derive the public key, and dropped. HMAC `kSigning` likewise stays in `Zeroizing`.

Other strict-mode behavior worth noting:
- Signature comparison uses a constant-time compare (`subtle::ConstantTimeEq`) for HMAC and ECDSA's own constant-time verification for SigV4A, to avoid timing side-channels on byte mismatches.
- The verifier reuses S3's standard error codes (`SignatureDoesNotMatch`, `RequestTimeTooSkewed`, `InvalidAccessKeyId`, `AuthorizationHeaderMalformed`, `ExpiredToken`) so existing AWS SDK clients surface clear errors.
- The proxy still re-signs outbound backend requests with `BACKEND_ACCESS_KEY_ID` / `BACKEND_SECRET_ACCESS_KEY`; client-side auth headers (including `x-amz-security-token` and `x-amz-region-set`) are stripped before forwarding.

### Cache invalidation

Writes (PUT, DELETE, multipart completion) purge the affected key from the on-disk cache. If the purge fails after one retry, a durable `.poisoned` marker file is written next to the cache entry. While the marker exists, `lookup()` treats the key as a miss so stale data is never served. The marker is cleared on successful purge, cache refill, or eviction. The marker survives process restarts.

### Cache directory permissions (Unix)

On Unix, the proxy creates cache files with mode `0600` and cache directories with mode `0700`. Group/other access is never granted to any path the proxy creates inside `CACHE_DIR`, regardless of the process umask. This applies to `<CACHE_DIR>/.lock`, `<CACHE_DIR>/.fill_id_counter`, shard directories (`objects/{d1}/{d2}/`), object body and metadata files, poison markers, the readiness probe, and aws-chunked upload spool files.

If `CACHE_DIR` already exists at startup with looser permissions (e.g. `0755`), the proxy logs a warning and leaves the operator-set permissions intact — it does not silently `chmod` directories you created. Operators who need group access to the cache tree should use filesystem ACLs, dedicated ownership (uid/gid), or pre-create the directory with the intended mode.

Existing cache files written by older proxy versions before this hardening are **not** recursively migrated. Only files created by the current proxy version get the tight modes; older files keep whatever mode the umask granted them at creation. Operators wanting full migration can `chmod -R go-rwx CACHE_DIR` before restarting the proxy.

On non-Unix targets the helpers fall back to the platform default (Windows uses ACLs, a different access-control model).

## Admin endpoints

The admin listener (default `:9090`) exposes:

- `GET /healthz` — liveness probe
- `GET /readyz` — readiness probe
- `GET /metrics` — Prometheus metrics

### Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `s3proxy_requests_total` | counter | `operation`, `status` | Total requests |
| `s3proxy_request_duration_seconds` | histogram | `operation` | Handler-setup latency (backend fetch + cache logic; excludes response body transfer) |
| `s3proxy_in_flight_requests` | gauge | | Handlers currently executing (decrements before streamed body completes) |
| `s3proxy_cache_total` | counter | `status` | Cache outcomes (`HIT`, `MISS`, `BYPASS`, `STALE`) |
| `s3proxy_request_size_bytes` | histogram | `operation` | Inbound body size |
| `s3proxy_response_size_bytes` | histogram | `operation` | Outbound body size |
| `s3proxy_cache_tmp_sweep_removed_files_total` | counter | `kind` | Stale tmp files removed at startup (see "Startup tmp sweep") |
| `s3proxy_cache_tmp_sweep_removed_bytes_total` | counter | `kind` | Bytes reclaimed by the startup tmp sweep |
| `s3proxy_cache_tmp_sweep_skipped_total` | counter | `reason` | Tmp entries preserved (symlink, non-regular, unknown_pattern, non_utf8) |
| `s3proxy_cache_tmp_sweep_failed_total` | counter | `reason` | Per-entry sweep I/O errors (read_dir, read_entry, metadata, remove) |

Cache hit rate: `rate(s3proxy_cache_total{status="HIT"}[5m]) / rate(s3proxy_cache_total[5m])`

## Architecture

```
┌──────────┐     ┌──────────────────────────────────────┐     ┌──────────┐
│          │     │           tiny-s3-proxy               │     │          │
│  Client  │────▶│  parse → auth → classify → handle    │────▶│ R2 / S3  │
│          │◀────│                                       │◀────│          │
└──────────┘     │  ┌─────────┐  ┌──────────────────┐   │     └──────────┘
                 │  │  cache   │  │   singleflight   │   │
                 │  │  (disk)  │  │ (miss coalescing) │   │
                 │  └─────────┘  └──────────────────┘   │
                 └──────────────────────────────────────┘
```

### Design decisions

- **Typed operation routing**, not a raw HTTP tunnel. Every S3 operation is parsed and dispatched explicitly. Unknown operations and requests with headers/query parameters the typed path cannot forward fall through to a locked-down raw passthrough (no redirect following, no system proxy, S3-specific SigV4 re-signing with single percent-encoding, no path normalization, `x-amz-content-sha256` payload hash). Invalid query parameters (e.g. `list-type=3`, `max-keys=abc`) are also routed through passthrough so the backend returns the appropriate error.
- **Streaming reads**. GET responses stream from backend to client (and to disk for cache fills) without buffering the full object in memory. Cache hits stream from disk. Write paths buffer the body in memory (capped by `MAX_REQUEST_BODY_BYTES`) for retry support — `Bytes::clone` is O(1) reference-counted.
- **LRU eviction with periodic stat reconciliation**. Cache hits update `last_accessed_at` on disk at most once per hour via atomic temp-file rename. Cache stats (`total_bytes`, `entry_count`) follow a periodic reconciliation model: the eviction scan walks the filesystem and overwrites the atomics with authoritative values, while `commit_fill`/`purge` do best-effort incremental adjustments between scans for responsiveness. This eliminates stat-accounting races without locks.
- **Generation-based cache invalidation**. Concurrent writes and cache fills are coordinated through per-key generation counters. A fill that started before a write is automatically rejected at commit time, preventing stale data from being re-cached after a PUT/DELETE.
- **Path-style and virtual-hosted-style**. Typed SDK operations honor `BACKEND_USE_PATH_STYLE`. Passthrough requests construct virtual-hosted-style URLs (`bucket.endpoint/key`) when path-style is disabled.
- **Startup tmp sweep**. After acquiring the single-owner `.lock`, the cache removes stale files from `<cache_dir>/tmp/` left by prior crashed runs. Only filename shapes that production writers can produce are removed; everything else (foreign files, symlinks, subdirectories) is preserved and warned about. The sweep is best-effort — I/O errors do not abort startup.

## Testing

```bash
# Unit tests (no external dependencies)
cargo test

# Integration tests (requires Docker + versity/versitygw image)
cargo test -- --ignored
```

The integration tests use [testcontainers](https://github.com/testcontainers/testcontainers-rs) to spin up [VersityGW](https://github.com/versity/versitygw) as an S3-compatible backend, build the full proxy stack in-process, and exercise end-to-end S3 operations including CRUD, caching, cache purge, multipart, and bucket validation.

**CI recommendation**: run `cargo test -- --ignored` in your CI pipeline with Docker available. The integration suite catches real proxy/backend/cache interaction bugs that unit tests cannot.

## License

MIT
