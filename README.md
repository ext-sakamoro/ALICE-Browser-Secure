# ALICE Browser Secure

Secure browser isolation powered by ALICE-Browser.

**License**: AGPL-3.0

---

## Architecture

```
Browser
  └── Frontend (Next.js)          :3000
        └── API Gateway           :8080
              └── Browser Engine  :8082   (Rust/Axum)
```

| Service | Port | Technology |
|---------|------|-----------|
| Frontend | 3000 | Next.js 14, TypeScript, Tailwind CSS |
| API Gateway | 8080 | Reverse proxy / auth middleware |
| Browser Engine | 8082 | Rust, Axum, Tokio |

---

## Endpoints

All endpoints are served at `:8082` (or through the gateway at `:8080`).

### `POST /api/v1/browser/isolate`

Start an isolated browser session for the given URL.

**Request**
```json
{
  "url": "https://example.com",
  "timeout_ms": 10000,
  "viewport_width": 1280,
  "viewport_height": 720
}
```

**Response**
```json
{
  "status": "ok",
  "url": "https://example.com",
  "session_id": "session-a1b2c3d4",
  "timeout_ms": 10000,
  "viewport_width": 1280,
  "viewport_height": 720,
  "isolated": true
}
```

### `POST /api/v1/browser/analyze`

Scan a URL for trackers, ads, and fingerprinting risk.

**Request**
```json
{ "url": "https://example.com" }
```

**Response**
```json
{
  "status": "ok",
  "url": "https://example.com",
  "tracker_count": 3,
  "ad_count": 1,
  "fingerprint_risk": "low",
  "safe": true
}
```

### `GET /api/v1/browser/blocklist`

Retrieve the full list of blocked domains.

**Response**
```json
{
  "count": 15,
  "domains": ["doubleclick.net", "googleadservices.com", "..."]
}
```

### `POST /api/v1/browser/filter`

Filter raw HTML through a set of blocking rules.

**Request**
```json
{
  "html": "<html>...</html>",
  "rules": ["##.ad-banner", "##[data-tracking]"]
}
```

**Response**
```json
{
  "status": "ok",
  "original_bytes": 48200,
  "filtered_bytes": 45000,
  "removed_elements": 6,
  "rules_applied": 2
}
```

### `GET /health`

Liveness check.

```json
{ "status": "ok", "uptime_secs": 17 }
```

---

## Running Locally

### Browser Engine

```bash
cd services/core-engine
BROWSER_ADDR=0.0.0.0:8082 cargo run --release
```

### Frontend

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BROWSER_ADDR` | `0.0.0.0:8082` | Bind address for the browser engine |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | API gateway base URL |
| `RUST_LOG` | `browser_engine=info` | Logging filter |

---

## License

AGPL-3.0. See [LICENSE](./LICENSE).
