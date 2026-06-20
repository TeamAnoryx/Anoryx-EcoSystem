"use client";

import { useState } from "react";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <span className="inline-flex items-center">
      <button
        type="button"
        onClick={onCopy}
        className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:text-fg"
      >
        {copied ? "Copied ✓" : label}
      </button>
      {/* Status message announced to AT (WCAG 4.1.3) without relying on the button. */}
      <span className="sr-only" role="status" aria-live="polite">
        {copied ? "Copied to clipboard" : ""}
      </span>
    </span>
  );
}
