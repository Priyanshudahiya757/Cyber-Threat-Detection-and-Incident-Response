/**
 * src/api/endpoints.ts
 *
 * Purpose:
 *   Single source of truth for backend route paths, mirroring
 *   backend/app/main.py's router registration (prefix /api/v1, one
 *   router per bounded context). Every service module imports paths
 *   from here instead of inlining strings, so a backend route rename
 *   only needs updating in one place.
 */
export const ENDPOINTS = {
  auth: {
    login: "/auth/login",
    refresh: "/auth/refresh",
    logout: "/auth/logout",
    me: "/auth/me",
    changePassword: "/auth/change-password",
  },
  users: {
    list: "/users",
    assignable: "/users/assignable",
    detail: (username: string) => `/users/${encodeURIComponent(username)}`,
    resetPassword: (username: string) => `/users/${encodeURIComponent(username)}/reset-password`,
  },
  logs: {
    upload: "/logs/upload",
    search: "/logs/search",
    batches: "/logs/batches",
  },
  detections: {
    list: "/detections",
    run: "/detections/run",
  },
  alerts: {
    list: "/alerts",
    channels: "/alerts/channels",
    test: "/alerts/test",
    acknowledge: (id: string) => `/alerts/${id}/acknowledge`,
  },
  ml: {
    train: "/ml/train",
    predict: "/ml/predict",
    models: "/ml/models",
    evaluate: "/ml/evaluate",
  },
  incidents: {
    list: "/incidents",
    detail: (ref: string) => `/incidents/${ref}`,
    status: (ref: string) => `/incidents/${ref}/status`,
    notes: (ref: string) => `/incidents/${ref}/notes`,
    assign: (ref: string) => `/incidents/${ref}/assign`,
  },
  analytics: {
    summary: "/analytics/summary",
    topIps: "/analytics/top-ips",
    severityDistribution: "/analytics/severity-distribution",
    threatTimeline: "/analytics/threat-timeline",
    attackTypes: "/analytics/attack-types",
    recentEvents: "/analytics/recent-events",
  },
  rules: {
    list: "/rules",
    detail: (ruleName: string) => `/rules/${ruleName}`,
  },
} as const;
