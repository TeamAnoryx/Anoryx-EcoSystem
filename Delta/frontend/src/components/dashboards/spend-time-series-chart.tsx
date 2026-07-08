"use client";

import { useId, useState } from "react";

import { formatMinorUnits } from "@/lib/money";
import type { TimeSeriesPointView } from "@/lib/types";

/**
 * Single-hue line chart for D-008's spend-over-time view (dataviz skill: thin
 * marks, hairline recessive gridlines, hover crosshair + tooltip, direct
 * end-label, no legend needed for one series).
 *
 * Honesty note: the backend returns only buckets with at least one entry — a
 * zero-spend bucket is omitted, never returned as an explicit zero (see
 * Delta/src/delta/dashboards/store.py). Interpolating a straight line across a
 * multi-bucket gap would draw spend that never happened, so this chart BREAKS
 * the line wherever the gap between two adjacent points exceeds one bucket step
 * (a quiet period reads as a visible gap, not a smoothed lie).
 */

const WIDTH = 640;
const HEIGHT = 220;
const PAD = { top: 16, right: 16, bottom: 28, left: 8 };

export function SpendTimeSeriesChart({
  points,
  currency,
  bucketMs,
}: {
  points: TimeSeriesPointView[];
  currency: string;
  bucketMs: number;
}) {
  const titleId = useId();
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  if (points.length === 0) {
    return (
      <p className="flex h-[220px] items-center justify-center text-sm text-fg-faint">
        No spend recorded in this window.
      </p>
    );
  }

  const times = points.map((p) => new Date(p.bucket_start).getTime());
  const costs = points.map((p) => p.cost_cents);
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const maxCost = Math.max(...costs, 1);
  const spanT = Math.max(maxT - minT, 1);

  const plotW = WIDTH - PAD.left - PAD.right;
  const plotH = HEIGHT - PAD.top - PAD.bottom;

  const x = (t: number) => PAD.left + ((t - minT) / spanT) * plotW;
  const y = (c: number) => PAD.top + plotH - (c / maxCost) * plotH;

  // Break the path wherever a gap exceeds ~1.5 bucket steps (see module doc).
  const segments: Array<Array<{ t: number; c: number; i: number }>> = [];
  let current: Array<{ t: number; c: number; i: number }> = [];
  points.forEach((p, i) => {
    const t = times[i];
    if (current.length > 0 && t - current[current.length - 1].t > bucketMs * 1.5) {
      segments.push(current);
      current = [];
    }
    current.push({ t, c: p.cost_cents, i });
  });
  if (current.length > 0) segments.push(current);

  const last = points[points.length - 1];

  return (
    <div className="relative">
      <svg
        role="img"
        aria-labelledby={titleId}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="w-full"
        onMouseLeave={() => setHoverIdx(null)}
      >
        <title id={titleId}>Spend over time</title>

        {/* Gridlines — hairline, recessive, one-step-off-surface. */}
        {[0, 0.5, 1].map((f) => (
          <line
            key={f}
            x1={PAD.left}
            x2={WIDTH - PAD.right}
            y1={PAD.top + plotH * f}
            y2={PAD.top + plotH * f}
            stroke="#222b36"
            strokeWidth={1}
          />
        ))}

        {/* Line segments — 2px, round join/cap, broken across gaps. */}
        {segments.map((seg, si) => (
          <polyline
            key={si}
            points={seg.map((p) => `${x(p.t)},${y(p.c)}`).join(" ")}
            fill="none"
            stroke="#4cc2ff"
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />
        ))}

        {/* End marker — >=8px, filled, 2px surface ring. */}
        <circle cx={x(times[points.length - 1])} cy={y(last.cost_cents)} r={5} fill="#4cc2ff" stroke="#11161d" strokeWidth={2} />

        {/* Hover hit targets (bigger than the mark) + crosshair. */}
        {points.map((p, i) => (
          <rect
            key={i}
            x={x(times[i]) - plotW / points.length / 2}
            y={PAD.top}
            width={Math.max(plotW / points.length, 12)}
            height={plotH}
            fill="transparent"
            onMouseEnter={() => setHoverIdx(i)}
            onFocus={() => setHoverIdx(i)}
            tabIndex={0}
            aria-label={`${new Date(p.bucket_start).toLocaleString()}: ${formatMinorUnits(
              p.cost_cents,
              currency,
            )}, ${p.request_count} requests`}
          />
        ))}
        {hoverIdx !== null ? (
          <line
            x1={x(times[hoverIdx])}
            x2={x(times[hoverIdx])}
            y1={PAD.top}
            y2={PAD.top + plotH}
            stroke="#9aa7b4"
            strokeWidth={1}
          />
        ) : null}

        {/* Direct end-label — the one label this chart carries directly. */}
        <text
          x={Math.min(x(times[points.length - 1]) + 6, WIDTH - PAD.right - 2)}
          y={y(last.cost_cents) - 8}
          textAnchor="end"
          className="fill-fg text-[10px] font-medium"
        >
          {formatMinorUnits(last.cost_cents, currency)}
        </text>
      </svg>

      {hoverIdx !== null ? (
        <div
          role="tooltip"
          className="pointer-events-none absolute -translate-x-1/2 rounded-md border border-border bg-bg-inset px-2 py-1 text-xs shadow-lg"
          style={{
            left: `${(x(times[hoverIdx]) / WIDTH) * 100}%`,
            top: 4,
          }}
        >
          <div className="font-semibold text-fg">
            {formatMinorUnits(points[hoverIdx].cost_cents, currency)}
          </div>
          <div className="text-fg-muted">
            {points[hoverIdx].request_count} req · {new Date(points[hoverIdx].bucket_start).toLocaleString()}
          </div>
        </div>
      ) : null}
    </div>
  );
}
