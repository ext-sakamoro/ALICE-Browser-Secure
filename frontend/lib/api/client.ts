const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

// ── Request / Response types ──────────────────────────────────────────────────

export interface IsolateRequest {
  url: string;
  timeout_ms?: number;
  viewport_width?: number;
  viewport_height?: number;
}

export interface IsolateResponse {
  status: string;
  url: string;
  session_id: string;
  timeout_ms: number;
  viewport_width: number;
  viewport_height: number;
  isolated: boolean;
}

export interface AnalyzeRequest {
  url: string;
}

export interface AnalyzeResponse {
  status: string;
  url: string;
  tracker_count: number;
  ad_count: number;
  fingerprint_risk: "low" | "medium" | "high";
  safe: boolean;
}

export interface BlocklistResponse {
  count: number;
  domains: string[];
}

export interface FilterRequest {
  html: string;
  rules: string[];
}

export interface FilterResponse {
  status: string;
  original_bytes: number;
  filtered_bytes: number;
  removed_elements: number;
  rules_applied: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`POST ${path} failed (${res.status}): ${text}`);
  }
  return res.json() as Promise<T>;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, { method: "GET" });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GET ${path} failed (${res.status}): ${text}`);
  }
  return res.json() as Promise<T>;
}

// ── BrowserClient ─────────────────────────────────────────────────────────────

export const browserClient = {
  /** Start an isolated browser session for the given URL. */
  isolate(req: IsolateRequest): Promise<IsolateResponse> {
    return post<IsolateResponse>("/api/v1/browser/isolate", req);
  },

  /** Analyze a URL for trackers, ads, and fingerprinting risk. */
  analyze(req: AnalyzeRequest): Promise<AnalyzeResponse> {
    return post<AnalyzeResponse>("/api/v1/browser/analyze", req);
  },

  /** Retrieve the full list of blocked domains. */
  blocklist(): Promise<BlocklistResponse> {
    return get<BlocklistResponse>("/api/v1/browser/blocklist");
  },

  /** Filter raw HTML through a set of blocking rules. */
  filter(req: FilterRequest): Promise<FilterResponse> {
    return post<FilterResponse>("/api/v1/browser/filter", req);
  },
};
