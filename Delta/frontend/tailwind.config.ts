import type { Config } from "tailwindcss";

// Dark-mode-first operator console, mirroring Anoryx-Sentinel/frontend's design
// tokens (kept here, never inline-styled in components). WCAG 2.1 AA contrast.
const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: "#0b0f14",
          raised: "#11161d",
          inset: "#161c24",
        },
        border: {
          DEFAULT: "#222b36",
          strong: "#33404f",
        },
        fg: {
          DEFAULT: "#e6edf3",
          muted: "#9aa7b4",
          faint: "#6b7888",
        },
        accent: {
          DEFAULT: "#4cc2ff",
          fg: "#04121c",
        },
        ok: "#3fb950",
        warn: "#d29922",
        danger: "#f85149",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
        sans: ["ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
