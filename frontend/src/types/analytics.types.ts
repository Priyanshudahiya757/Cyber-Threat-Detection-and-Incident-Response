/**
 * src/types/analytics.types.ts
 *
 * Purpose:
 *   Shapes for the Dashboard and Analytics pages. backend/app/api/v1/
 *   analytics.py currently returns 501 for /summary, /top-ips, and
 *   /severity-distribution (implementation lands once ingestion volume
 *   exists to aggregate — see that file's own docstring). The two
 *   underlying Elasticsearch aggregation functions it will eventually
 *   call already exist (db/elastic.py::aggregate_top_ips /
 *   aggregate_severity_counts), so these shapes are modeled directly on
 *   what those functions already return, not guessed at.
 */

export interface DashboardSummary {
  total_logs: number;
  threats_detected: number;
  active_incidents: number;
  critical_alerts: number;
  ai_anomalies: number;
  log_sources: number;
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

export interface SystemHealthStatus {
  ingestion_pipeline: "healthy" | "degraded" | "down";
  rule_engine: "healthy" | "degraded" | "down";
  ml_engine: "healthy" | "degraded" | "down";
  elasticsearch: "healthy" | "degraded" | "down";
  mongodb: "healthy" | "degraded" | "down";
}
