/**
 * src/config/env.ts
 *
 * Purpose:
 *   Single point of access for environment variables (Vite exposes
 *   import.meta.env). Everything else in the app reads config through
 *   this module rather than touching import.meta.env directly, so env
 *   var names only exist in one place and are trivially greppable/typed.
 */

function readBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value === "true";
}

export const env = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? "/api/v1",
  useMocksForUnimplemented: readBoolean(import.meta.env.VITE_USE_MOCKS_FOR_UNIMPLEMENTED, false),
  isDev: import.meta.env.DEV,
} as const;
