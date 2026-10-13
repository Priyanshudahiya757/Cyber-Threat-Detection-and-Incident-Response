/**
 * src/services/detectionService.ts
 * Real Axios wrappers for /detections/* and /ml/* endpoints.
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type {
  AlertListResponse,
  DetectionListResponse,
  DetectionRuleInfo,
  DetectionRunResult,
  EvaluationMetrics,
  ModelMetadata,
  PredictAnomaliesResponse,
  TrainModelResponse,
} from "@/types";

export const detectionService = {
  async list(params?: {
    engine?: string;
    severity?: string;
    entity?: string;
    limit?: number;
  }): Promise<DetectionListResponse> {
    const response = await apiClient.get<DetectionListResponse>(ENDPOINTS.detections.list, { params });
    return response.data;
  },

  async listAlerts(limit = 100): Promise<AlertListResponse> {
    const response = await apiClient.get<AlertListResponse>(ENDPOINTS.detections.alerts, {
      params: { limit },
    });
    return response.data;
  },

  async listEngineRules(): Promise<{ rules: DetectionRuleInfo[] }> {
    const response = await apiClient.get<{ rules: DetectionRuleInfo[] }>(ENDPOINTS.detections.rules);
    return response.data;
  },

  async runDetection(minutes = 60): Promise<DetectionRunResult> {
    const response = await apiClient.post<DetectionRunResult>(ENDPOINTS.detections.run, null, {
      params: { minutes },
    });
    return response.data;
  },

  async trainModel(days = 7): Promise<TrainModelResponse> {
    const response = await apiClient.post<TrainModelResponse>(ENDPOINTS.ml.train, null, {
      params: { days },
    });
    return response.data;
  },

  async predict(minutes = 60): Promise<PredictAnomaliesResponse> {
    const response = await apiClient.post<PredictAnomaliesResponse>(ENDPOINTS.ml.predict, null, {
      params: { minutes },
    });
    return response.data;
  },

  async listModels(): Promise<{ models: ModelMetadata[] }> {
    const response = await apiClient.get<{ models: ModelMetadata[] }>(ENDPOINTS.ml.models);
    return response.data;
  },

  async latestModel(): Promise<ModelMetadata> {
    const response = await apiClient.get<ModelMetadata>(ENDPOINTS.ml.latestModel);
    return response.data;
  },

  async evaluate(): Promise<EvaluationMetrics> {
    const response = await apiClient.post<EvaluationMetrics>(ENDPOINTS.ml.evaluate);
    return response.data;
  },
};
