import type { Config } from "tailwindcss";

// Dark-mode-first operator console (Datadog-like). Design tokens live here, never
// inline-styled in components (frontend-design principle). WCAG 2.1 AA contrast.
const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Slate-based dark surface palette.
        bg: {
          DEFAULT: "#0b0f14", // app background
          raised: "#11161d", // cards / panels
          inset: "#161c24", // inputs / wells
        },
        border: {
          DEFAULT: "#222b36",
          strong: "#33404f",
        },
        fg: {
          DEFAULT: "#e6edf3", // primary text (AA on bg)
          muted: "#9aa7b4", // secondary text (AA on bg)
          faint: "#6b7888",
        },
        accent: {
          DEFAULT: "#4cc2ff", // links / focus
          fg: "#04121c",
        },
        ok: "#3fb950",
        warn: "#d29922",
        danger: "#f85149",
      },
      fontFamily: {
        // Monospace accents for IDs, tokens, audit data.
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
        sans: ["ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
