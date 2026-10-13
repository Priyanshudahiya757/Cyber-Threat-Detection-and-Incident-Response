/**
 * src/api/client.ts
 *
 * Purpose:
 *   The one axios instance the entire app uses. Two interceptors do all
 *   the auth heavy lifting so individual service modules
 *   (authService.ts, logService.ts, etc.) never think about tokens:
 *
 *   1. Request interceptor: attaches `Authorization: Bearer <token>` to
 *      every outgoing request, matching backend/app/core/dependencies.py
 *      ::oauth2_scheme's expectation exactly.
 *
 *   2. Response interceptor: on a 401, attempts exactly one silent
 *      refresh via POST /auth/refresh (backend/app/api/v1/auth.py) and
 *      replays the original request. If refresh itself fails (refresh
 *      token expired/invalid), it clears stored tokens and redirects to
 *      /login — matching the backend's refresh-token expiry policy
 *      (JWT_REFRESH_TOKEN_EXPIRE_DAYS in backend/app/core/config.py).
 *
 * Connects to:
 *   - Every service module in src/services/ imports `apiClient` from here
 *   - src/api/tokenStorage.ts for reading/writing tokens
 */
import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { env } from "@/config/env";
import { tokenStorage } from "./tokenStorage";
import type { TokenResponse } from "@/types";

export const apiClient = axios.create({
  baseURL: env.apiBaseUrl,
  timeout: 30_000,
});

apiClient.interceptors.request.use((config) => {
  const token = tokenStorage.getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

type RetriableConfig = InternalAxiosRequestConfig & { _retried?: boolean };

// Serializes concurrent refresh attempts: if five requests 401 at once,
// only the first triggers a real refresh call; the rest await its result.
let refreshInFlight: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  const refreshToken = tokenStorage.getRefreshToken();
  if (!refreshToken) {
    throw new Error("No refresh token available");
  }

  // Deliberately bypasses `apiClient` (a fresh axios call) to avoid
  // re-triggering this same response interceptor recursively.
  const response = await axios.post<TokenResponse>(
    `${env.apiBaseUrl}/auth/refresh`,
    { refresh_token: refreshToken },
    { timeout: 10_000 }
  );

  tokenStorage.save(
    { accessToken: response.data.access_token, refreshToken: response.data.refresh_token },
    localStorage.getItem("sentinelgrid.remember") === "true"
  );

  return response.data.access_token;
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as RetriableConfig | undefined;

    if (error.response?.status !== 401 || !originalRequest || originalRequest._retried) {
      return Promise.reject(error);
    }

    // Never attempt to refresh the refresh call itself.
    if (originalRequest.url?.includes("/auth/refresh")) {
      tokenStorage.clear();
      window.location.href = "/login";
      return Promise.reject(error);
    }

    originalRequest._retried = true;

    try {
      refreshInFlight = refreshInFlight ?? refreshAccessToken();
      const newAccessToken = await refreshInFlight;
      refreshInFlight = null;

      originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
      return apiClient(originalRequest);
    } catch (refreshError) {
      refreshInFlight = null;
      tokenStorage.clear();
      window.location.href = "/login";
      return Promise.reject(refreshError);
    }
  }
);
