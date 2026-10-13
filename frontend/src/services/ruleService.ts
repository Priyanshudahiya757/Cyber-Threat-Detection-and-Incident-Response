/**
 * src/services/ruleService.ts
 * Real Axios wrappers for /rules/* admin configuration endpoints.
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { DetectionRuleInfo } from "@/types";

export interface RuleConfigInfo extends DetectionRuleInfo {
  config?: Record<string, unknown>;
}

export const ruleService = {
  async list(): Promise<{ rules: RuleConfigInfo[] }> {
    const response = await apiClient.get<{ rules: RuleConfigInfo[] }>(ENDPOINTS.rules.list);
    return response.data;
  },

  async update(
    ruleName: string,
    body: { enabled?: boolean; config?: Record<string, unknown> }
  ): Promise<RuleConfigInfo> {
    const response = await apiClient.patch<RuleConfigInfo>(ENDPOINTS.rules.detail(ruleName), body);
    return response.data;
  },
};
