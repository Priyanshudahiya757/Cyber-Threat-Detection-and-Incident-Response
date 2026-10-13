/**
 * src/services/authService.ts
 *
 * Purpose:
 *   Thin wrapper over the real backend auth endpoints
 *   (backend/app/api/v1/auth.py). Unlike incidentService.ts or
 *   analyticsService.ts, this service has NO mock fallback — auth is
 *   fully implemented on the backend (Phase 1), so every function here
 *   always hits the real API.
 *
 * Connects to:
 *   - src/api/client.ts for the underlying HTTP call
 *   - src/features/auth/context/AuthContext.tsx is the only consumer;
 *     components never call this service directly (they use useAuth()).
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { LoginRequest, TokenResponse, UserPublic } from "@/types";

export const authService = {
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    const response = await apiClient.post<TokenResponse>(ENDPOINTS.auth.login, credentials);
    return response.data;
  },

  async getCurrentUser(): Promise<UserPublic> {
    const response = await apiClient.get<UserPublic>(ENDPOINTS.auth.me);
    return response.data;
  },
};
