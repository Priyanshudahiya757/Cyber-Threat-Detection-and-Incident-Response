/**
 * src/types/analytics.types.ts
 * Response shapes of backend/app/api/v1/analytics.py.
 */
import type { SourceType } from "./common.types";

export interface DashboardSummary {
  total_logs: number;
  log_sources: number;
  logs_by_source: Partial<Record<SourceType, number>>;
  threats_detected: number;
  ai_anomalies: number;
  active_incidents: number;
  critical_alerts: number;
  unacknowledged_alerts: number;
}

export interface TopIpEntry {
  ip: string;
  count: number;
}

export interface SeverityDistribution {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface TimeSeriesPoint {
  timestamp: string;
  count: number;
}

export interface AttackTypeEntry {
  threat_type: string;
  count: number;
  mitre_technique: string;
}

export interface SystemHealth {
  status: "ready" | "degraded";
  version: string;
  checks: Record<string, string>;
}
