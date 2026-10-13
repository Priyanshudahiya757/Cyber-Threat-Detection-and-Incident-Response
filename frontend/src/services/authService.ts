/**
 * src/services/authService.ts
 * Session endpoints (backend/app/api/v1/auth.py). Components go through
 * useAuth() rather than calling this directly.
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { ChangePasswordRequest, LoginRequest, TokenResponse, UserPublic } from "@/types";

export const authService = {
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    const response = await apiClient.post<TokenResponse>(ENDPOINTS.auth.login, credentials);
    return response.data;
  },

  /** Revokes the refresh token server-side so it is useless after sign-out. */
  async logout(refreshToken: string): Promise<void> {
    await apiClient.post(ENDPOINTS.auth.logout, { refresh_token: refreshToken });
  },

  async getCurrentUser(): Promise<UserPublic> {
    const response = await apiClient.get<UserPublic>(ENDPOINTS.auth.me);
    return response.data;
  },

  /** Returns a fresh token pair: every token issued before the change stops working. */
  async changePassword(body: ChangePasswordRequest): Promise<TokenResponse> {
    const response = await apiClient.post<TokenResponse>(ENDPOINTS.auth.changePassword, body);
    return response.data;
  },
};
