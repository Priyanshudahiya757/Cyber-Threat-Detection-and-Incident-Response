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

export type TokenPair = { accessToken: string; refreshToken: string };

function isRemembered(): boolean {
  return localStorage.getItem(REMEMBER_KEY) === "true";
}

function activeStorage(): Storage {
  return isRemembered() ? localStorage : sessionStorage;
}

function write(storage: Storage, tokens: TokenPair): void {
  storage.setItem(ACCESS_TOKEN_KEY, tokens.accessToken);
  storage.setItem(REFRESH_TOKEN_KEY, tokens.refreshToken);
}

export const tokenStorage = {
  /** Store the tokens issued at login, in the storage the "Remember me" choice selects. */
  save(tokens: TokenPair, remember: boolean): void {
    // The flag itself always lives in localStorage so a later page load
    // knows which storage holds the tokens.
    localStorage.setItem(REMEMBER_KEY, String(remember));
    write(remember ? localStorage : sessionStorage, tokens);
  },

  /** Replace the tokens of the current session (refresh, password change), keeping the "Remember me" choice. */
  replace(tokens: TokenPair): void {
    write(activeStorage(), tokens);
  },

  getAccessToken(): string | null {
    return activeStorage().getItem(ACCESS_TOKEN_KEY);
  },

  getRefreshToken(): string | null {
    return activeStorage().getItem(REFRESH_TOKEN_KEY);
  },

  clear(): void {
    for (const storage of [localStorage, sessionStorage]) {
      storage.removeItem(ACCESS_TOKEN_KEY);
      storage.removeItem(REFRESH_TOKEN_KEY);
    }
    localStorage.removeItem(REMEMBER_KEY);
  },
};
