/**
 * src/services/alertService.ts
 * Alerts and their external delivery channels (backend/app/api/v1/alerts.py).
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { AlertChannelResult, AlertChannelStatus, AlertListResponse, AlertRecord } from "@/types";

export const alertService = {
  async list(params: { acknowledged?: boolean; limit?: number } = {}): Promise<AlertListResponse> {
    const response = await apiClient.get<AlertListResponse>(ENDPOINTS.alerts.list, { params });
    return response.data;
  },

  async acknowledge(id: string): Promise<AlertRecord> {
    const response = await apiClient.post<AlertRecord>(ENDPOINTS.alerts.acknowledge(id));
    return response.data;
  },

  async channels(): Promise<AlertChannelStatus[]> {
    const response = await apiClient.get<{ channels: AlertChannelStatus[] }>(ENDPOINTS.alerts.channels);
    return response.data.channels;
  },

  /** Admin-only: sends a labelled test message through every configured channel. */
  async sendTest(): Promise<AlertChannelResult[]> {
    const response = await apiClient.post<{ results: AlertChannelResult[] }>(ENDPOINTS.alerts.test);
    return response.data.results;
  },
};
