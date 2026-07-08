/**
 * Vitest jsdom render lane setup.
 *
 * Imports @testing-library/jest-dom so that its custom matchers
 * (toBeInTheDocument, toHaveTextContent, etc.) are available in all
 * *.test.tsx files without per-file imports.
 */
import "@testing-library/jest-dom";
