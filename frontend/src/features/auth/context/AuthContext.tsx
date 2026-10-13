/**
 * src/features/auth/context/AuthContext.tsx
 *
 * Purpose:
 *   Holds the authenticated user in React state and exposes login/logout.
 *   On mount, if a token is already stored (returning visitor), it
 *   silently calls GET /auth/me to rehydrate the user rather than
 *   forcing a re-login — the access token interceptor in api/client.ts
 *   handles refreshing it transparently if it's expired.
 *
 * Connects to:
 *   - src/services/authService.ts for the actual API calls
 *   - src/api/tokenStorage.ts for persisting tokens
 *   - src/features/auth/hooks/useAuth.ts is the consumption point —
 *     components use that hook, never this context directly.
 *   - src/routes/ProtectedRoute.tsx gates routes on isAuthenticated
 */
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { authService } from "@/services/authService";
import { tokenStorage } from "@/api/tokenStorage";
import { queryClient } from "@/lib/queryClient";
import { AuthContext } from "./AuthContextValue";
import type { ChangePasswordRequest, LoginRequest, UserPublic } from "@/types";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserPublic | null>(null);
  // Starts true so ProtectedRoute doesn't flash a redirect-to-login
  // before we've had a chance to check for an existing stored token.
  const [isInitializing, setIsInitializing] = useState(true);

  useEffect(() => {
    if (!tokenStorage.getAccessToken()) {
      setIsInitializing(false);
      return;
    }

    authService
      .getCurrentUser()
      .then(setUser)
      .catch(() => {
        // Token invalid/expired and refresh (handled by the response
        // interceptor) also failed — clear and fall through to login.
        tokenStorage.clear();
        setUser(null);
      })
      .finally(() => setIsInitializing(false));
  }, []);

  const login = useCallback(async (credentials: LoginRequest, remember: boolean) => {
    const response = await authService.login(credentials);
    tokenStorage.save(
      { accessToken: response.access_token, refreshToken: response.refresh_token },
      remember
    );
    setUser(response.user);
  }, []);

  const logout = useCallback(() => {
    const refreshToken = tokenStorage.getRefreshToken();
    if (refreshToken) {
      // Best effort: the local session ends even if the server can't be reached.
      authService.logout(refreshToken).catch(() => undefined);
    }
    tokenStorage.clear();
    // Cached API data belongs to the session that is ending.
    queryClient.clear();
    setUser(null);
  }, []);

  const changePassword = useCallback(async (body: ChangePasswordRequest) => {
    const response = await authService.changePassword(body);
    // The server just invalidated every older token, including ours.
    tokenStorage.replace({ accessToken: response.access_token, refreshToken: response.refresh_token });
    setUser(response.user);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, isAuthenticated: user !== null, isInitializing, login, logout, changePassword }}
    >
      {children}
    </AuthContext.Provider>
  );
}
