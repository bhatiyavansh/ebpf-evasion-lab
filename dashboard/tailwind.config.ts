import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#090b0f",
          raised: "#0e1117",
          panel: "#12161d",
          inset: "#0b0e13",
          border: "#1d222b",
          hover: "#161b23",
        },
        ink: {
          DEFAULT: "#e8ecf1",
          muted: "#9aa4b1",
          faint: "#636d7b",
        },
        accent: {
          DEFAULT: "#2dd4bf",
          bright: "#5eead4",
          muted: "#1a4d49",
          dim: "#0f2e2b",
        },
        status: {
          detected: "#36c98d",
          observed: "#38bdf8",
          partial: "#e0b23a",
          nottested: "#5a6472",
          missed: "#f0674f",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      keyframes: {
        pulsedot: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        fadein: {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        pulsedot: "pulsedot 1.4s ease-in-out infinite",
        fadein: "fadein 0.25s ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
