/**
 * src/services/mockUtils.ts
 *
 * Purpose:
 *   Shared helpers for service modules that fall back to mock data when
 *   a backend endpoint isn't implemented yet (per project requirement:
 *   "If an endpoint is not implemented yet, temporarily use mock data
 *   through a service layer that can later be replaced with real API
 *   calls without changing the UI components").
 *
 *   The pattern every such service follows (see incidentService.ts,
 *   analyticsService.ts, ruleConfigService.ts, userService.ts):
 *
 *     export async function listIncidents(params) {
 *       if (!env.useMocksForUnimplemented) {
 *         return apiClient.get(ENDPOINTS.incidents.list, { params }).then(r => r.data);
 *       }
 *       await simulateNetworkDelay();
 *       return mockIncidents(params);
 *     }
 *
 *   Flipping VITE_USE_MOCKS_FOR_UNIMPLEMENTED to "false" once a backend
 *   phase lands switches every such function to the real call — no
 *   component using the corresponding hook needs to change, since hooks
 *   only ever import the service function, never branch on mock/real
 *   themselves.
 */

/** Simulates realistic network latency so loading states are visibly exercised in demo mode. */
export function simulateNetworkDelay(minMs = 250, maxMs = 700): Promise<void> {
  const delay = minMs + Math.random() * (maxMs - minMs);
  return new Promise((resolve) => setTimeout(resolve, delay));
}

/** Deterministic pseudo-random generator (seeded) so demo data is stable across reloads, not re-randomized every render. */
export function seededRandom(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state / 0x7fffffff;
  };
}

export function pickOne<T>(items: readonly T[], rand: () => number): T {
  return items[Math.floor(rand() * items.length)];
}

export function randomInt(min: number, max: number, rand: () => number): number {
  return Math.floor(min + rand() * (max - min + 1));
}
