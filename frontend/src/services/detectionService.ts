/**
 * src/services/detectionService.ts
 * Stored detections and the two engines that produce them
 * (backend/app/api/v1/detections.py and ml.py).
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type {
  DetectionEngineType,
  DetectionListResponse,
  DetectionRunResult,
  EvaluationMetrics,
  ModelMetadata,
  Severity,
  TrainModelResponse,
} from "@/types";

export const detectionService = {
  async list(params?: {
    engine?: DetectionEngineType;
    severity?: Severity;
    entity?: string;
    limit?: number;
  }): Promise<DetectionListResponse> {
    const response = await apiClient.get<DetectionListResponse>(ENDPOINTS.detections.list, { params });
    return response.data;
  },

  /** Re-run the rule engine over logs ingested in the last `minutes`. */
  async runRules(minutes: number): Promise<DetectionRunResult> {
    const response = await apiClient.post<DetectionRunResult>(ENDPOINTS.detections.run, null, {
      params: { minutes },
    });
    return response.data;
  },

  /** Score logs ingested in the last `minutes` with the latest trained model. */
  async runAnomalyScoring(minutes: number): Promise<DetectionRunResult> {
    const response = await apiClient.post<DetectionRunResult>(ENDPOINTS.ml.predict, null, {
      params: { minutes },
    });
    return response.data;
  },

  /** Admin-only: train a new model version on logs ingested in the last `days`. */
  async trainModel(days: number): Promise<TrainModelResponse> {
    const response = await apiClient.post<TrainModelResponse>(ENDPOINTS.ml.train, null, {
      params: { days },
    });
    return response.data;
  },

  async listModels(): Promise<ModelMetadata[]> {
    const response = await apiClient.get<{ models: ModelMetadata[] }>(ENDPOINTS.ml.models);
    return response.data.models;
  },

  async evaluate(): Promise<EvaluationMetrics> {
    const response = await apiClient.post<EvaluationMetrics>(ENDPOINTS.ml.evaluate);
    return response.data;
  },
};
