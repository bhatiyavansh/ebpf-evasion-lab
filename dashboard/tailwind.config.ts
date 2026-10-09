import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#0b0d11",
          raised: "#111419",
          panel: "#15181e",
          border: "#23272f",
        },
        ink: {
          DEFAULT: "#e6e9ee",
          muted: "#9aa3af",
          faint: "#6b7280",
        },
        accent: {
          DEFAULT: "#5b8def",
          muted: "#3a4a63",
        },
        status: {
          detected: "#3fb950",
          observed: "#5b8def",
          partial: "#d7a32e",
          nottested: "#5a6270",
          missed: "#e5534b",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
