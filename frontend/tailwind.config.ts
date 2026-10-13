import type { Config } from "tailwindcss";

/**
 * Design token system for the SOC console.
 *
 * Palette is a deliberate cyan/blue duotone on a navy (not pure black)
 * base — pure black + one neon accent is the generic "AI dashboard"
 * default; pairing a cool navy surface with BOTH a cyan (data/info) and
 * a blue (primary actions) accent, plus the semantic red/orange/green
 * severity set the brief calls for, reads as an actual SIEM console
 * (Sentinel/Elastic/QRadar all use this navy+dual-accent pattern for the
 * same reason: long analyst shifts need low eye strain, and severity
 * colors need to pop clearly against everything else).
 *
 * Typography pairs a monospace face for data-dense content (timestamps,
 * IPs, log IDs, numeric stats — anything an analyst scans character by
 * character) with a humanist sans for UI chrome (nav, labels, buttons).
 * This split is tied to the subject: a console where operators read
 * structured/tabular security data all day benefits from the same
 * fixed-width legibility a terminal gives you, not just a stylistic choice.
 */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          950: "#080B12",
          900: "#0A0E17",
          800: "#111827",
          700: "#161D2E",
          600: "#1B2436",
          500: "#232C3F",
        },
        border: {
          DEFAULT: "#232C3F",
          subtle: "#1B2436",
        },
        text: {
          primary: "#E7ECF5",
          secondary: "#8D96AC",
          muted: "#5B6478",
        },
        accent: {
          cyan: "#22D3EE",
          "cyan-dim": "#0E7490",
          blue: "#3B82F6",
          "blue-dim": "#1D4ED8",
        },
        severity: {
          critical: "#F04438",
          "critical-dim": "#7A271A",
          high: "#F97066",
          warning: "#F79009",
          "warning-dim": "#7A4504",
          medium: "#FDB022",
          low: "#3B82F6",
          success: "#12B76A",
          "success-dim": "#095C37",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.02em" }],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34, 211, 238, 0.15), 0 0 12px rgba(34, 211, 238, 0.12)",
        "glow-critical": "0 0 0 1px rgba(240, 68, 56, 0.25), 0 0 16px rgba(240, 68, 56, 0.15)",
        panel: "0 1px 2px rgba(0, 0, 0, 0.4), 0 4px 16px rgba(0, 0, 0, 0.25)",
      },
      animation: {
        "pulse-slow": "pulse 2.4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "ping-slow": "ping 2.4s cubic-bezier(0, 0, 0.2, 1) infinite",
      },
      backgroundImage: {
        "grid-fade":
          "linear-gradient(to bottom, transparent, rgba(8,11,18,0.9)), repeating-linear-gradient(0deg, rgba(34,211,238,0.035) 0px, rgba(34,211,238,0.035) 1px, transparent 1px, transparent 32px), repeating-linear-gradient(90deg, rgba(34,211,238,0.035) 0px, rgba(34,211,238,0.035) 1px, transparent 1px, transparent 32px)",
      },
    },
  },
  plugins: [],
} satisfies Config;
