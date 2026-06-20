"use client";

import { useEffect, useRef } from "react";

/**
 * Minimal accessible modal (role=dialog, focus trap-ish, Esc to close). Used for
 * the one-time key-secret reveal (R5). Content is rendered as text only — never
 * dangerouslySetInnerHTML (R6).
 */
export function Modal({
  title,
  onClose,
  closeLabel = "Close",
  children,
}: {
  title: string;
  onClose: () => void;
  closeLabel?: string;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const node = ref.current;
    node?.focus();

    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      // Focus trap (WCAG 2.1.2): keep Tab/Shift+Tab cycling within the dialog.
      if (e.key === "Tab" && node) {
        const focusable = node.querySelectorAll<HTMLElement>(
          'button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (focusable.length === 0) {
          e.preventDefault();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement;
        if (e.shiftKey) {
          if (active === first || active === node) {
            e.preventDefault();
            last.focus();
          }
        } else if (active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
      onClick={onClose}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-lg border border-border bg-bg-raised p-6 shadow-xl"
      >
        <div className="flex items-start justify-between">
          <h2 className="text-base font-semibold text-fg">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:text-fg"
          >
            {closeLabel}
          </button>
        </div>
        <div className="mt-4">{children}</div>
      </div>
    </div>
  );
}
