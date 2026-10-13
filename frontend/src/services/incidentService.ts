/**
 * src/services/incidentService.ts
 * Incident workflow (backend/app/api/v1/incidents.py).
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { IncidentListParams, IncidentRecord, IncidentStatusUpdateRequest } from "@/types";

export const incidentService = {
  async list(params: IncidentListParams = {}): Promise<{ incidents: IncidentRecord[]; count: number }> {
    const response = await apiClient.get<{ incidents: IncidentRecord[]; count: number }>(
      ENDPOINTS.incidents.list,
      { params }
    );
    return response.data;
  },

  async get(ref: string): Promise<IncidentRecord> {
    const response = await apiClient.get<IncidentRecord>(ENDPOINTS.incidents.detail(ref));
    return response.data;
  },

  async updateStatus(ref: string, body: IncidentStatusUpdateRequest): Promise<IncidentRecord> {
    const response = await apiClient.patch<IncidentRecord>(ENDPOINTS.incidents.status(ref), body);
    return response.data;
  },

  async addNote(ref: string, note: string): Promise<IncidentRecord> {
    const response = await apiClient.post<IncidentRecord>(ENDPOINTS.incidents.notes(ref), { note });
    return response.data;
  },

  async assign(ref: string, assignedTo: string): Promise<IncidentRecord> {
    const response = await apiClient.patch<IncidentRecord>(ENDPOINTS.incidents.assign(ref), {
      assigned_to: assignedTo,
    });
    return response.data;
  },
};
