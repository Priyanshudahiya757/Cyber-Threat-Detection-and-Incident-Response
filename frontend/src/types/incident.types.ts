/**
 * src/types/incident.types.ts
 *
 * Purpose:
 *   Mirrors backend/app/models/incident_schema.py exactly, even though
 *   backend/app/api/v1/incidents.py currently returns 501 Not Implemented
 *   for every route (Phase 7 is not built yet — see docs/architecture.md
 *   §2.4 for the planned detection-to-incident correlation design).
 *
 *   Keeping this type file byte-for-byte aligned with the backend schema
 *   now means src/services/incidentService.ts's mock implementation can
 *   be swapped for real fetch calls later with NO changes to any
 *   component that consumes useIncidents()/useIncident() — only the
 *   service layer changes.
 */
import type { Severity } from "./common.types";
import type { DetectionEntity } from "./detection.types";

export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "CLOSED";

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

export interface IncidentNoteRequest {
  note: string;
}
