/**
 * src/services/logService.ts
 * Real Axios wrappers for /logs/* endpoints.
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type {
  IngestionBatch,
  LogSearchParams,
  LogSearchResponse,
  LogUploadResponse,
  SourceType,
} from "@/types";

export const logService = {
  async upload(file: File, sourceType: SourceType, sourceHost?: string): Promise<LogUploadResponse> {
    const form = new FormData();
    form.append("file", file);
    form.append("source_type", sourceType);
    if (sourceHost) form.append("source_host", sourceHost);
    const response = await apiClient.post<LogUploadResponse>(ENDPOINTS.logs.upload, form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return response.data;
  },

  async search(params: LogSearchParams = {}): Promise<LogSearchResponse> {
    const response = await apiClient.get<LogSearchResponse>(ENDPOINTS.logs.search, { params });
    return response.data;
  },

  async listBatches(): Promise<{ batches: IngestionBatch[] }> {
    const response = await apiClient.get<{ batches: IngestionBatch[] }>(ENDPOINTS.logs.batches);
    return response.data;
  },
};
