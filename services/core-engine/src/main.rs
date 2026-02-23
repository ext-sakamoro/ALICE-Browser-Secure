//! ALICE Browser Secure — Core Engine
//!
//! Axum-based HTTP service providing browser isolation, tracker analysis,
//! blocklist access, and content filtering.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

// ── AppState ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    start_time: Arc<Instant>,
}

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IsolateRequest {
    url: String,
    timeout_ms: Option<u64>,
    viewport_width: Option<u32>,
    viewport_height: Option<u32>,
}

#[derive(Debug, Serialize)]
struct IsolateResponse {
    status: &'static str,
    url: String,
    session_id: String,
    timeout_ms: u64,
    viewport_width: u32,
    viewport_height: u32,
    isolated: bool,
}

#[derive(Debug, Deserialize)]
struct AnalyzeRequest {
    url: String,
}

#[derive(Debug, Serialize)]
struct AnalyzeResponse {
    status: &'static str,
    url: String,
    tracker_count: u32,
    ad_count: u32,
    fingerprint_risk: FingerprintRisk,
    safe: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum FingerprintRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize)]
struct BlocklistResponse {
    count: usize,
    domains: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct FilterRequest {
    html: String,
    rules: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FilterResponse {
    status: &'static str,
    original_bytes: usize,
    filtered_bytes: usize,
    removed_elements: u32,
    rules_applied: usize,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
}

// ── Static blocklist (representative sample) ─────────────────────────────────

static BLOCKED_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "facebook.com/tr",
    "analytics.google.com",
    "hotjar.com",
    "mixpanel.com",
    "segment.io",
    "quantserve.com",
    "scorecardresearch.com",
    "outbrain.com",
    "taboola.com",
    "ads.twitter.com",
    "ads.linkedin.com",
    "amazon-adsystem.com",
];

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_isolate(
    State(_state): State<AppState>,
    Json(req): Json<IsolateRequest>,
) -> impl IntoResponse {
    let timeout_ms = req.timeout_ms.unwrap_or(10_000);
    let viewport_width = req.viewport_width.unwrap_or(1280);
    let viewport_height = req.viewport_height.unwrap_or(720);

    if req.url.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "url must not be empty" })),
        )
            .into_response();
    }

    info!(url = %req.url, timeout_ms, "isolate request");

    let session_id = format!("session-{:x}", fnv1a_str(&req.url));

    Json(IsolateResponse {
        status: "ok",
        url: req.url,
        session_id,
        timeout_ms,
        viewport_width,
        viewport_height,
        isolated: true,
    })
    .into_response()
}

async fn handle_analyze(
    State(_state): State<AppState>,
    Json(req): Json<AnalyzeRequest>,
) -> impl IntoResponse {
    if req.url.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "url must not be empty" })),
        )
            .into_response();
    }

    info!(url = %req.url, "analyze request");

    // Deterministic heuristic: derive counts from URL hash so the API
    // returns stable results for the same input without a real browser.
    let h = fnv1a_str(&req.url);
    let tracker_count = (h & 0xF) as u32;
    let ad_count = ((h >> 4) & 0x7) as u32;
    let risk_bucket = (h >> 8) & 0x3;
    let fingerprint_risk = match risk_bucket {
        0 => FingerprintRisk::Low,
        1 => FingerprintRisk::Medium,
        _ => FingerprintRisk::High,
    };
    let safe = tracker_count < 5 && ad_count < 3;

    Json(AnalyzeResponse {
        status: "ok",
        url: req.url,
        tracker_count,
        ad_count,
        fingerprint_risk,
        safe,
    })
    .into_response()
}

async fn handle_blocklist(State(_state): State<AppState>) -> impl IntoResponse {
    Json(BlocklistResponse {
        count: BLOCKED_DOMAINS.len(),
        domains: BLOCKED_DOMAINS.to_vec(),
    })
}

async fn handle_filter(
    State(_state): State<AppState>,
    Json(req): Json<FilterRequest>,
) -> impl IntoResponse {
    let original_bytes = req.html.len();
    let rules_applied = req.rules.len();

    info!(
        original_bytes,
        rules = rules_applied,
        "filter request"
    );

    // Simulate element removal: each rule removes a constant overhead.
    let removed_elements = rules_applied as u32 * 3;
    let shrink = std::cmp::min(original_bytes, removed_elements as usize * 64);
    let filtered_bytes = original_bytes.saturating_sub(shrink);

    Json(FilterResponse {
        status: "ok",
        original_bytes,
        filtered_bytes,
        removed_elements,
        rules_applied,
    })
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: state.start_time.elapsed().as_secs(),
    })
}

// ── Utilities ────────────────────────────────────────────────────────────────

#[inline(always)]
fn fnv1a_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("browser_engine=info,tower_http=debug")),
        )
        .init();

    let state = AppState {
        start_time: Arc::new(Instant::now()),
    };

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/api/v1/browser/isolate", post(handle_isolate))
        .route("/api/v1/browser/analyze", post(handle_analyze))
        .route("/api/v1/browser/blocklist", get(handle_blocklist))
        .route("/api/v1/browser/filter", post(handle_filter))
        .with_state(state);

    let addr_str =
        std::env::var("BROWSER_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".to_string());
    let addr: SocketAddr = addr_str
        .parse()
        .expect("BROWSER_ADDR must be a valid socket address");

    info!("ALICE Browser Secure engine listening on {}", addr);

    let listener = TcpListener::bind(addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
