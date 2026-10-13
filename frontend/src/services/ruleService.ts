/**
 * src/services/ruleService.ts
 * Detection rule state and settings (backend/app/api/v1/rules.py).
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { DetectionRule, RuleSettingValue } from "@/types";

export const ruleService = {
  async list(): Promise<DetectionRule[]> {
    const response = await apiClient.get<{ rules: DetectionRule[] }>(ENDPOINTS.rules.list);
    return response.data.rules;
  },

  /** Admin-only. Changes apply to the running engine immediately. */
  async update(
    ruleName: string,
    body: { enabled?: boolean; config?: Record<string, RuleSettingValue> }
  ): Promise<DetectionRule> {
    const response = await apiClient.patch<DetectionRule>(ENDPOINTS.rules.detail(ruleName), body);
    return response.data;
  },
};
