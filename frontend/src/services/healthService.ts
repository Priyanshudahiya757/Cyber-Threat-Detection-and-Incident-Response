/**
 * src/services/healthService.ts
 * Platform readiness probe. Served outside /api/v1 and without auth,
 * so it bypasses apiClient.
 */
import type { SystemHealth } from "@/types";

export const HEALTH_QUERY_KEY = ["health", "ready"] as const;

export async function fetchSystemHealth(): Promise<SystemHealth> {
  const response = await fetch("/health/ready");
  // 503 is a valid answer here: it carries the per-dependency breakdown.
  if (!response.ok && response.status !== 503) {
    throw new Error("Health check failed");
  }
  return (await response.json()) as SystemHealth;
}
