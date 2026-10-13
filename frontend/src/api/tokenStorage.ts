/**
 * src/api/tokenStorage.ts
 *
 * Purpose:
 *   Wraps token persistence behind a small interface so the rest of the
 *   app (api/client.ts's interceptors, AuthContext) never touches
 *   localStorage/sessionStorage directly. Backs the Login page's
 *   "Remember me" checkbox: checked -> localStorage (survives browser
 *   restart), unchecked -> sessionStorage (cleared when the tab closes).
 */

const ACCESS_TOKEN_KEY = "sentinelgrid.access_token";
const REFRESH_TOKEN_KEY = "sentinelgrid.refresh_token";
const REMEMBER_KEY = "sentinelgrid.remember";

type TokenPair = { accessToken: string; refreshToken: string };

function activeStorage(): Storage {
  const remembered = localStorage.getItem(REMEMBER_KEY) === "true";
  return remembered ? localStorage : sessionStorage;
}

export const tokenStorage = {
  save(tokens: TokenPair, remember: boolean): void {
    // The "remember" flag itself always lives in localStorage (it has to
    // survive independently of which storage the tokens end up in) so a
    // later page load knows which storage to check first.
    localStorage.setItem(REMEMBER_KEY, String(remember));
    const storage = remember ? localStorage : sessionStorage;
    storage.setItem(ACCESS_TOKEN_KEY, tokens.accessToken);
    storage.setItem(REFRESH_TOKEN_KEY, tokens.refreshToken);
  },

  getAccessToken(): string | null {
    return activeStorage().getItem(ACCESS_TOKEN_KEY);
  },

  getRefreshToken(): string | null {
    return activeStorage().getItem(REFRESH_TOKEN_KEY);
  },

  clear(): void {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(REMEMBER_KEY);
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};
