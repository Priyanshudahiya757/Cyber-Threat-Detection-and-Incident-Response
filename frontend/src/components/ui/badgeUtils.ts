import type { Severity } from "@/types";

export type BadgeTone = Severity | "warning" | "info" | "neutral" | "success";

/** Maps a backend Severity value onto the Badge tone prop. */
export function severityToTone(severity: Severity): BadgeTone {
  return severity;
}
