import { describe, expect, it } from "vitest";

import { formatCompactCount, formatMinorUnits, formatMinorUnitsCompact } from "@/lib/money";

describe("formatMinorUnits", () => {
  it("formats integer cents as a currency string", () => {
    expect(formatMinorUnits(123456, "USD")).toBe("$1,234.56");
  });

  it("falls back to a plain rendering for an invalid currency code", () => {
    expect(formatMinorUnits(100, "NOTREAL")).toBe("1.00 NOTREAL");
  });
});

describe("formatMinorUnitsCompact", () => {
  it("compacts large amounts (D-008 stat tiles)", () => {
    expect(formatMinorUnitsCompact(420_000_00, "USD")).toBe("$420.0K");
  });

  it("keeps full cent precision below $1,000 (never a lossily-rounded value)", () => {
    expect(formatMinorUnitsCompact(1234, "USD")).toBe("$12.34");
  });
});

describe("formatCompactCount", () => {
  it("compacts large counts", () => {
    expect(formatCompactCount(12_900)).toBe("12.9K");
  });

  it("leaves small counts as plain grouped numbers", () => {
    expect(formatCompactCount(22)).toBe("22");
  });
});
