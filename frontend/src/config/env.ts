/**
 * src/config/env.ts
 *
 * Purpose:
 *   Single point of access for environment variables (Vite exposes
 *   import.meta.env). Everything else in the app reads config through
 *   this module rather than touching import.meta.env directly, so env
 *   var names only exist in one place and are trivially greppable/typed.
 */
export const env = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? "/api/v1",
  isDev: import.meta.env.DEV,
} as const;
