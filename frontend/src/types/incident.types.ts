/**
 * src/types/incident.types.ts
 * Incident documents as returned by backend/app/api/v1/incidents.py
 * (built by backend/app/incidents/correlator.py).
 */
import type { Severity } from "./common.types";
import type { DetectionEntity } from "./detection.types";

export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "CLOSED";

export const INCIDENT_STATUSES: readonly IncidentStatus[] = ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"];

export interface InvestigationNote {
  author: string;
  note: string;
  created_at: string;
}

export interface IncidentRecord {
  id: string;
  incident_ref: string; // e.g. "INC-1001"
  threat_type: string;
  severity: Severity;
  mitre_technique?: string | null;
  entity: DetectionEntity;
  status: IncidentStatus;
  detection_ids: string[];
  evidence_log_ids: string[];
  description: string | null;
  investigation_notes: InvestigationNote[];
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

export interface IncidentListParams {
  status?: IncidentStatus;
  severity?: Severity;
  assigned_to?: string;
}

export interface IncidentStatusUpdateRequest {
  status: IncidentStatus;
  note?: string;
}
