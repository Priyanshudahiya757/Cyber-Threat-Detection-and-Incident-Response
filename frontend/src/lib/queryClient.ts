/**
 * src/lib/queryClient.ts
 *
 * Purpose:
 *   Single QueryClient instance for the app. Defaults are tuned for a
 *   security console: staleTime of 30s means dashboard/table data
 *   doesn't feel stale on quick navigation but still refetches often
 *   enough to matter for "live" monitoring views (those pages set a
 *   shorter/refetchInterval override individually).
 */
import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 0,
    },
  },
});
