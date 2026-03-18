# tiny-s3-proxy

A caching S3 reverse proxy. Tiny as in footprint, not as in complexity.

## What it does

Sits between your application and an S3-compatible backend (R2, MinIO, etc.) and does three things well:

1. **Caches GET responses on disk** for configured prefixes, so repeated reads never hit the backend.
2. **Coalesces concurrent cache misses** — if 20 workers request the same uncached object simultaneously, one request hits the backend. The rest wait and read from the freshly-filled cache.
3. **Serves stale on backend failure** — if the backend is down and there's a cached copy, you get data instead of an error.

Everything else (PUT, DELETE, LIST, multipart, any S3 operation the proxy doesn't explicitly handle) passes through to the backend with retries.

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

GET responses for cacheable prefixes (default: `script_bundle/`, `bun_bundle/`, `tar/`) are streamed to disk and to the client simultaneously. Cache hits stream directly from disk — the proxy never buffers a full object in memory.

Writes (PUT, DELETE, multipart completion) purge the cache for the affected key immediately.

## Quick start

```bash
# Required
export FRONTEND_BUCKET=my-bucket
export BACKEND_ENDPOINT=https://xxx.r2.cloudflarestorage.com
export BACKEND_BUCKET=my-bucket
export BACKEND_ACCESS_KEY_ID=your-key
export BACKEND_SECRET_ACCESS_KEY=your-secret

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
| `AUTH_MODE` | `trusted_internal` | `trusted_internal` or `access_key_allowlist` |
| `ALLOWED_FRONTEND_KEYS` | | Comma-separated access key IDs (for `access_key_allowlist` mode) |

### Backend

| Variable | Default | Description |
|---|---|---|
| `BACKEND_ENDPOINT` | *required* | S3-compatible endpoint URL |
| `BACKEND_REGION` | `auto` | AWS region |
| `BACKEND_BUCKET` | *required* | Actual backend bucket name |
| `BACKEND_ACCESS_KEY_ID` | *required* | Backend credentials |
| `BACKEND_SECRET_ACCESS_KEY` | *required* | Backend credentials |
| `BACKEND_USE_PATH_STYLE` | `true` | Use path-style S3 addressing |
| `BACKEND_ALLOW_HTTP` | `false` | Allow plaintext HTTP to backend |

### Cache

| Variable | Default | Description |
|---|---|---|
| `CACHE_DIR` | `/cache` | Disk cache directory |
| `CACHE_MAX_BYTES` | `10737418240` (10 GB) | Maximum cache size on disk |
| `CACHE_MAX_OBJECT_BYTES` | `536870912` (512 MB) | Maximum single object size to cache |
| `CACHEABLE_PREFIXES` | `script_bundle/,bun_bundle/,tar/` | Object key prefixes to cache |
| `CACHE_SERVE_STALE_ON_ERROR` | `true` | Serve stale cache entries when backend fails |
| `CACHE_EVICTION_INTERVAL_SECS` | `300` | Seconds between LRU eviction passes |

### Retry

| Variable | Default | Description |
|---|---|---|
| `GET_MAX_ATTEMPTS` | `3` | Retry attempts for GET |
| `HEAD_MAX_ATTEMPTS` | `3` | Retry attempts for HEAD |
| `LIST_MAX_ATTEMPTS` | `3` | Retry attempts for LIST |
| `PUT_MAX_ATTEMPTS` | `1` | Retry attempts for PUT |
| `DELETE_MAX_ATTEMPTS` | `2` | Retry attempts for DELETE |
| `RETRY_BASE_BACKOFF_MS` | `100` | Base backoff for exponential retry |
| `UPSTREAM_CONNECT_TIMEOUT_MS` | `5000` | Backend connect timeout |
| `UPSTREAM_REQUEST_TIMEOUT_MS` | `30000` | Backend request timeout |

## Admin endpoints

The admin listener (default `:9090`) exposes:

- `GET /healthz` — liveness probe
- `GET /readyz` — readiness probe
- `GET /metrics` — Prometheus metrics

### Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `s3proxy_requests_total` | counter | `operation`, `status`, `method` | Total requests |
| `s3proxy_request_duration_seconds` | histogram | `operation` | Request latency |
| `s3proxy_in_flight_requests` | gauge | | Currently processing |
| `s3proxy_cache_total` | counter | `status` | Cache outcomes (`HIT`, `MISS`, `BYPASS`, `STALE`) |
| `s3proxy_request_size_bytes` | histogram | `operation` | Inbound body size |
| `s3proxy_response_size_bytes` | histogram | `operation` | Outbound body size |

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

- **Typed operation routing**, not a raw HTTP tunnel. Every S3 operation is parsed and dispatched explicitly. Unknown operations fall through to a raw passthrough with SigV4 re-signing.
- **Streaming everywhere**. GET responses stream from backend to client (and to disk for cache fills) without buffering the full object in memory. Cache hits stream from disk.
- **Lock-free hot path**. Cache statistics use atomic counters. No metadata is written to disk on cache hits. The singleflight registry is the only mutex in the read path.
- **Path-style only**. No virtual-hosted-style bucket addressing.

## Testing

```bash
# Unit tests (no external dependencies)
cargo test

# Integration tests (requires Docker + versity/versitygw image)
cargo test -- --ignored
```

The integration tests use [testcontainers](https://github.com/testcontainers/testcontainers-rs) to spin up [VersityGW](https://github.com/versity/versitygw) as an S3-compatible backend, build the full proxy stack in-process, and exercise end-to-end S3 operations.

## License

MIT
