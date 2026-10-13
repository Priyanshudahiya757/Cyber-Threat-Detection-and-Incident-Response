/**
 * src/types/common.types.ts
 *
 * Purpose:
 *   Types shared across multiple feature domains — severity levels and
 *   API envelope shapes that mirror backend conventions exactly (see
 *   backend/app/models/log_schema.py::Severity and the list-endpoint
 *   response shapes used throughout backend/app/api/v1/*.py).
 */

export type Severity = "low" | "medium" | "high" | "critical";

export type SourceType = "windows" | "linux" | "firewall" | "web_server";

/** Generic paginated/countable list envelope matching backend list endpoints. */
export interface ListResponse<T> {
  count: number;
  items: T[];
}

/** Standard FastAPI error response shape (HTTPException detail). */
export interface ApiErrorResponse {
  detail: string;
}

/**
 * Marks data returned by the mock-data fallback layer rather than a real
 * backend call, so UI components (and the "connected/mock" indicator in
 * dev tooling) can distinguish them without inspecting call sites.
 */
export interface MockMeta {
  __isMockData: true;
}
