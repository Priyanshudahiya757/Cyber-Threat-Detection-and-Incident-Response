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
import { createContext, useCallback, useEffect, useState, type ReactNode } from "react";
import { authService } from "@/services/authService";
import { tokenStorage } from "@/api/tokenStorage";
import type { LoginRequest, UserPublic } from "@/types";

export interface AuthContextValue {
  user: UserPublic | null;
  isAuthenticated: boolean;
  isInitializing: boolean;
  login: (credentials: LoginRequest, remember: boolean) => Promise<void>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserPublic | null>(null);
  // Starts true so ProtectedRoute doesn't flash a redirect-to-login
  // before we've had a chance to check for an existing stored token.
  const [isInitializing, setIsInitializing] = useState(true);

  useEffect(() => {
    const existingToken = tokenStorage.getAccessToken();
    if (!existingToken) {
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
    tokenStorage.clear();
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, isAuthenticated: user !== null, isInitializing, login, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}
