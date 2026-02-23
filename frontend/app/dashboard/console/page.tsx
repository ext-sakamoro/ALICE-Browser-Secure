"use client";

import { useBrowserStore } from "@/lib/hooks/use-store";
import { browserClient } from "@/lib/api/client";

const DEFAULT_URL = "https://example.com";

export default function BrowserConsolePage() {
  const {
    url,
    timeout,
    viewportWidth,
    viewportHeight,
    result,
    loading,
    setUrl,
    setTimeout,
    setViewportWidth,
    setViewportHeight,
    setResult,
    setLoading,
  } = useBrowserStore();

  async function handleIsolate() {
    setLoading(true);
    setResult(null);
    try {
      const res = await browserClient.isolate({
        url: url || DEFAULT_URL,
        timeout_ms: timeout,
        viewport_width: viewportWidth,
        viewport_height: viewportHeight,
      });
      setResult(res as unknown as Record<string, unknown>);
    } catch (err) {
      setResult({ error: String(err) });
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalyze() {
    setLoading(true);
    setResult(null);
    try {
      const res = await browserClient.analyze({ url: url || DEFAULT_URL });
      setResult(res as unknown as Record<string, unknown>);
    } catch (err) {
      setResult({ error: String(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4">
        <h1 className="text-xl font-semibold">Browser Console</h1>
        <p className="text-sm text-gray-400">
          Isolate sessions and analyze URLs for trackers
        </p>
      </header>

      <div className="mx-auto max-w-3xl px-6 py-8 space-y-8">
        {/* URL */}
        <div>
          <label className="mb-1 block text-sm font-medium text-gray-300">
            Target URL
          </label>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        {/* Timeout + Viewport */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">
              Timeout (ms)
            </label>
            <input
              type="number"
              min={500}
              max={60000}
              value={timeout}
              onChange={(e) => setTimeout(Number(e.target.value))}
              className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">
              Viewport Width
            </label>
            <input
              type="number"
              min={320}
              max={3840}
              value={viewportWidth}
              onChange={(e) => setViewportWidth(Number(e.target.value))}
              className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">
              Viewport Height
            </label>
            <input
              type="number"
              min={240}
              max={2160}
              value={viewportHeight}
              onChange={(e) => setViewportHeight(Number(e.target.value))}
              className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex gap-4">
          <button
            onClick={handleIsolate}
            disabled={loading}
            className="flex-1 rounded-lg bg-emerald-600 py-3 font-semibold text-white hover:bg-emerald-500 disabled:opacity-50 transition-colors"
          >
            {loading ? "Processing..." : "Isolate"}
          </button>
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="flex-1 rounded-lg bg-gray-700 py-3 font-semibold text-white hover:bg-gray-600 disabled:opacity-50 transition-colors"
          >
            {loading ? "Processing..." : "Analyze"}
          </button>
        </div>

        {/* Result panel */}
        {result && (
          <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
            <h2 className="mb-3 text-lg font-semibold">Result</h2>
            <pre className="overflow-auto text-sm text-emerald-400">
              {JSON.stringify(result, null, 2)}
            </pre>
          </section>
        )}
      </div>
    </div>
  );
}
