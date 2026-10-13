/**
 * src/types/log.types.ts
 *
 * Purpose:
 *   Mirrors backend/app/models/log_schema.py (NormalizedLog,
 *   LogUploadResponse, IngestionBatch) and the query params accepted by
 *   GET /api/v1/logs/search (backend/app/api/v1/logs.py).
 */
import type { Severity, SourceType } from "./common.types";

export type EventCategory = "authentication" | "network" | "web_attack" | "system";

export interface NormalizedLog {
  log_id: string;
  source_type: SourceType;
  source_host: string | null;
  event_category: EventCategory;
  event_type: string;
  severity: Severity;
  user: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  dest_port: number | null;
  raw_log: string;
  parsed_fields: Record<string, unknown>;
  timestamp: string; // ISO 8601
  ingested_at: string; // ISO 8601
}

export interface LogUploadResponse {
  accepted: number;
  rejected: number;
  duplicates: number;
  errors: string[];
  log_ids: string[];
  batch_id: string | null;
}

export interface LogSearchParams {
  query?: string;
  source_type?: SourceType;
  severity?: Severity;
  source_ip?: string;
  start_time?: string;
  end_time?: string;
  size?: number;
  from?: number;
}

export interface LogSearchResponse {
  total: number;
  results: NormalizedLog[];
}

export interface IngestionBatch {
  batch_id: string;
  source_type: SourceType;
  source_host: string | null;
  filename: string | null;
  uploaded_by: string;
  total_records: number;
  accepted: number;
  rejected: number;
  duplicates: number;
  errors: string[];
  created_at: string;
}
