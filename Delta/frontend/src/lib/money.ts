/**
 * Pure display helpers for integer-minor-units money (non-negotiable #3, D-007).
 *
 * Every money field in this app is an integer minor-units count end-to-end
 * (Delta's contract — see Delta/src/delta/money.py). Conversion to a human
 * dollar/major-unit string happens ONLY here, at render time. The result of
 * these functions must never be parsed back into a number and sent to the API
 * — always send the original integer minor-units value.
 *
 * This is a client-side cost estimate / display convenience, not a source of
 * truth: currency formatting (e.g. locale grouping) can differ slightly from
 * what a finance system would print. Two-decimal currencies are assumed
 * (ISO 4217 minor unit == 1/100); this is a known, honest limitation for any
 * zero- or three-decimal currency the API may accept as a plain string.
 */

export function formatMinorUnits(amountMinorUnits: number, currency: string): string {
  const major = amountMinorUnits / 100;
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: currency || "USD",
      currencyDisplay: "narrowSymbol",
    }).format(major);
  } catch {
    // Unknown/invalid currency code — fall back to a plain, honest rendering
    // rather than throwing in the UI.
    return `${major.toFixed(2)} ${currency}`;
  }
}
