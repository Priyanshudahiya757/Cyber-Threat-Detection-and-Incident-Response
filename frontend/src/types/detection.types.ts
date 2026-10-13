/**
 * src/types/detection.types.ts
 * Mirrors backend/app/models/detection_schema.py and alert_schema.py,
 * plus the response shapes of the detections, alerts, rules and ml routers.
 */
import type { Severity } from "./common.types";

export type DetectionEngineType = "rule" | "ml";

export type EntityType = "ip" | "user" | "host";

export interface DetectionEntity {
  type: EntityType;
  value: string;
}

export interface DetectionEvent {
  detection_id: string;
  engine: DetectionEngineType;
  rule_name: string | null;
  anomaly_score: number | null;
  risk_percentage: number | null;
  confidence: number;
  severity: Severity;
  mitre_technique: string | null;
  entity: DetectionEntity;
  evidence_log_ids: string[];
  explanation: string;
  timestamp: string;
}

export interface DetectionListResponse {
  detections: DetectionEvent[];
  count: number;
}

/** Result of a manual rule re-scan or ML scoring run. Only findings not already stored are counted. */
export interface DetectionRunResult {
  logs_scanned: number;
  detections_found: number;
  alerts_generated: number;
  detections: DetectionEvent[];
}

// --- Alerts (backend/app/api/v1/alerts.py) ---

export interface AlertRecord {
  _id: string;
  title: string;
  threat_type: string;
  severity: Severity;
  entity: DetectionEntity;
  detection_id: string;
  mitre_technique: string | null;
  description: string;
  dispatched_channels?: string[];
  acknowledged?: boolean;
  acknowledged_by?: string | null;
  created_at: string;
}

export interface AlertListResponse {
  alerts: AlertRecord[];
  count: number;
  unacknowledged_total: number;
}

export interface AlertChannelStatus {
  channel: string;
  configured: boolean;
}

export interface AlertChannelResult extends AlertChannelStatus {
  delivered: boolean;
  error: string | null;
}

// --- Detection rules (backend/app/api/v1/rules.py) ---

export type RuleSettingValue = number | string[];

export type RuleSettingSpec =
  | { type: "integer"; default: number; min: number; max: number }
  | { type: "string_list"; default: string[] };

export interface DetectionRule {
  rule_name: string;
  description: string;
  mitre_technique: string;
  enabled: boolean;
  config: Record<string, RuleSettingValue>;
  settings: Record<string, RuleSettingSpec>;
}

// --- ML / anomaly detection (backend/app/api/v1/ml.py) ---

export interface ModelMetadata {
  model_type: string;
  version: string;
  trained_at: string;
  feature_names: string[];
  n_samples: number;
  params: Record<string, number>;
  metrics: Record<string, number>;
  file: string;
}

export interface TrainModelResponse {
  version: string;
  model_type: string;
  n_samples: number;
  n_features: number;
  anomaly_ratio: number;
  entities_flagged_anomalous: string[];
}

export interface EvaluationMetrics {
  n_samples: number;
  n_true_anomalies: number;
  n_predicted_anomalies: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: [[number, number], [number, number]]; // [[TN, FP], [FN, TP]]
}
