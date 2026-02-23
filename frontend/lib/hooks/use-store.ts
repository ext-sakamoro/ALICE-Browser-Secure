"use client";

import { create } from "zustand";

// ── State shape ───────────────────────────────────────────────────────────────

interface BrowserState {
  url: string;
  timeout: number;
  viewportWidth: number;
  viewportHeight: number;
  result: Record<string, unknown> | null;
  loading: boolean;

  setUrl: (v: string) => void;
  setTimeout: (v: number) => void;
  setViewportWidth: (v: number) => void;
  setViewportHeight: (v: number) => void;
  setResult: (v: Record<string, unknown> | null) => void;
  setLoading: (v: boolean) => void;
  reset: () => void;
}

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_URL = "";
const DEFAULT_TIMEOUT = 10_000;
const DEFAULT_VIEWPORT_WIDTH = 1280;
const DEFAULT_VIEWPORT_HEIGHT = 720;

// ── Store ─────────────────────────────────────────────────────────────────────

export const useBrowserStore = create<BrowserState>((set) => ({
  url: DEFAULT_URL,
  timeout: DEFAULT_TIMEOUT,
  viewportWidth: DEFAULT_VIEWPORT_WIDTH,
  viewportHeight: DEFAULT_VIEWPORT_HEIGHT,
  result: null,
  loading: false,

  setUrl: (v) => set({ url: v }),
  setTimeout: (v) => set({ timeout: v }),
  setViewportWidth: (v) => set({ viewportWidth: v }),
  setViewportHeight: (v) => set({ viewportHeight: v }),
  setResult: (v) => set({ result: v }),
  setLoading: (v) => set({ loading: v }),

  reset: () =>
    set({
      url: DEFAULT_URL,
      timeout: DEFAULT_TIMEOUT,
      viewportWidth: DEFAULT_VIEWPORT_WIDTH,
      viewportHeight: DEFAULT_VIEWPORT_HEIGHT,
      result: null,
      loading: false,
    }),
}));
