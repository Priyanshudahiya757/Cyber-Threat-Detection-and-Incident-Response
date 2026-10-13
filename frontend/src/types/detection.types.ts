/**
 * src/types/detection.types.ts
 *
 * Purpose:
 *   Mirrors backend/app/models/detection_schema.py and
 *   backend/app/models/alert_schema.py, plus the response shapes of
 *   backend/app/api/v1/detections.py and backend/app/api/v1/ml.py.
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

export interface AlertRecord {
  _id: string;
  title: string;
  threat_type: string;
  severity: Severity;
  entity: DetectionEntity;
  detection_id: string;
  mitre_technique: string | null;
  description: string;
  channel_dispatched: boolean;
  created_at: string;
}

export interface AlertListResponse {
  alerts: AlertRecord[];
  count: number;
}

export interface DetectionRuleInfo {
  rule_name: string;
  description: string;
  mitre_technique: string;
  enabled: boolean;
}

export interface DetectionRunResult {
  logs_scanned: number;
  detections_found: number;
  alerts_generated: number;
  detections: DetectionEvent[];
}

// --- ML / anomaly detection (backend/app/api/v1/ml.py) ---

export interface ModelMetadata {
  model_type: string;
  version: string;
  trained_at: string;
  feature_names: string[];
  n_samples: number;
  params: Record<string, number>;
  metrics: {
    anomaly_ratio?: number;
    mean_decision_score?: number;
    std_decision_score?: number;
    [key: string]: number | undefined;
  };
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

export interface PredictAnomaliesResponse {
  logs_scanned: number;
  anomalies_found: number;
  alerts_generated: number;
  detections: DetectionEvent[];
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
