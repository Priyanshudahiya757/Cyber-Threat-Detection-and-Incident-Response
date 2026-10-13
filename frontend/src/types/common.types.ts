/**
 * src/types/common.types.ts
 * Types shared across feature domains, mirroring
 * backend/app/models/log_schema.py.
 */
export type Severity = "low" | "medium" | "high" | "critical";

export type SourceType = "windows" | "linux" | "firewall" | "web_server";

export const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];

export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  windows: "Windows",
  linux: "Linux",
  firewall: "Firewall",
  web_server: "Web Server",
};
