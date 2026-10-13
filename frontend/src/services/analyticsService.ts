/**
 * src/services/analyticsService.ts
 * Real Axios wrappers for /analytics/* dashboard endpoints.
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type {
  AttackTypeEntry,
  DashboardSummary,
  DetectionEvent,
  SeverityDistribution,
  TimeSeriesPoint,
  TopIpEntry,
} from "@/types";

export const analyticsService = {
  async summary(hours = 24): Promise<DashboardSummary> {
    const response = await apiClient.get<DashboardSummary>(ENDPOINTS.analytics.summary, {
      params: { hours },
    });
    return response.data;
  },

  async topIps(hours = 24, topN = 10): Promise<{ items: TopIpEntry[]; count: number }> {
    const response = await apiClient.get<{ items: TopIpEntry[]; count: number }>(
      ENDPOINTS.analytics.topIps,
      { params: { hours, top_n: topN } }
    );
    return response.data;
  },

  async severityDistribution(hours = 24): Promise<SeverityDistribution> {
    const response = await apiClient.get<SeverityDistribution>(
      ENDPOINTS.analytics.severityDistribution,
      { params: { hours } }
    );
    return response.data;
  },

  async threatTimeline(hours = 24): Promise<{ items: TimeSeriesPoint[]; count: number }> {
    const response = await apiClient.get<{ items: TimeSeriesPoint[]; count: number }>(
      ENDPOINTS.analytics.threatTimeline,
      { params: { hours } }
    );
    return response.data;
  },

  async attackTypes(limit = 10): Promise<{ items: AttackTypeEntry[]; count: number }> {
    const response = await apiClient.get<{ items: AttackTypeEntry[]; count: number }>(
      ENDPOINTS.analytics.attackTypes,
      { params: { limit } }
    );
    return response.data;
  },

  async recentEvents(limit = 15): Promise<{ events: DetectionEvent[]; count: number }> {
    const response = await apiClient.get<{ events: DetectionEvent[]; count: number }>(
      ENDPOINTS.analytics.recentEvents,
      { params: { limit } }
    );
    return response.data;
  },
};
