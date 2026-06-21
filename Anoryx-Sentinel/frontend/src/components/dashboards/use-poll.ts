"use client";

import { useEffect, useRef, useState } from "react";

import { ClientApiError } from "@/lib/client-api";
import { shouldPollTick } from "@/lib/dashboards";
import { toFriendlyError } from "@/lib/errors";

/**
 * Visibility-aware polling hook (F-013 R7, threat vector 7).
 *
 * Discipline:
 *  - Pauses while the tab is hidden (`document.hidden`); resumes on show.
 *  - One AbortController per request; the in-flight request is cancelled on
 *    unmount and on `resetKey` change (tenant switch — R3).
 *  - No request stacking: a tick is skipped while a prior request is in flight.
 *  - State is cleared whenever `resetKey` changes, so prior-tenant data never
 *    survives a switch (R3).
 *
 * `fetcher` is read through a ref so it need not be a hook dependency; the effect
 * re-arms only on `resetKey` / `intervalMs`.
 */
export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

export function usePoll<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  intervalMs: number,
  resetKey: string,
): PollState<T> {
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const inFlight = useRef(false);
  const [state, setState] = useState<PollState<T>>({ data: null, error: null, loading: true });

  useEffect(() => {
    // Reset on key change so no prior-tenant data lingers (R3, vector 3).
    setState({ data: null, error: null, loading: true });
    inFlight.current = false;

    let cancelled = false;
    let controller: AbortController | null = null;

    async function tick() {
      const hidden = typeof document !== "undefined" && document.hidden;
      if (cancelled || !shouldPollTick(hidden, inFlight.current)) return;
      inFlight.current = true;
      controller = new AbortController();
      try {
        const result = await fetcherRef.current(controller.signal);
        if (!cancelled) setState({ data: result, error: null, loading: false });
      } catch (err) {
        if (cancelled) return;
        if (err instanceof DOMException && err.name === "AbortError") return;
        // R5: never surface a raw engine/stack message. ClientApiError already
        // carries the BFF-mapped safe string (preserves 401 reauth wording);
        // anything else is funnelled through toFriendlyError's generic mapping.
        const message =
          err instanceof ClientApiError ? err.message : toFriendlyError(err).message;
        setState((s) => ({ ...s, error: message, loading: false }));
      } finally {
        inFlight.current = false;
      }
    }

    void tick();
    const id = setInterval(() => void tick(), intervalMs);
    const onVisible = () => {
      if (!document.hidden) void tick();
    };
    document.addEventListener("visibilitychange", onVisible);

    return () => {
      cancelled = true;
      clearInterval(id);
      controller?.abort();
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [intervalMs, resetKey]);

  return state;
}
