/**
 * src/routes/AppRouter.tsx
 *
 * Purpose:
 *   Declares every route in the app. Paths are driven by the same
 *   NAV_ITEMS list Sidebar.tsx renders from, so the two structures can't
 *   silently drift apart (a nav link pointing at a route that doesn't exist).
 */
import { Routes, Route, Navigate } from "react-router-dom";
import { lazy, Suspense } from "react";
import { AppShell } from "@/components/layout/AppShell";
import { ProtectedRoute } from "./ProtectedRoute";
import { AdminRoute } from "./AdminRoute";
import { NotFoundPage } from "./NotFoundPage";

import { LoginPage } from "@/features/auth/pages/LoginPage";

const DashboardPage = lazy(() => import("@/features/dashboard/pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const LiveMonitoringPage = lazy(() => import("@/features/monitoring/pages/LiveMonitoringPage").then((module) => ({ default: module.LiveMonitoringPage })));
const UploadLogsPage = lazy(() => import("@/features/logs/pages/UploadLogsPage").then((module) => ({ default: module.UploadLogsPage })));
const ThreatDetectionPage = lazy(() => import("@/features/detections/pages/ThreatDetectionPage").then((module) => ({ default: module.ThreatDetectionPage })));
const AnomalyDetectionPage = lazy(() => import("@/features/anomalies/pages/AnomalyDetectionPage").then((module) => ({ default: module.AnomalyDetectionPage })));
const IncidentManagementPage = lazy(() => import("@/features/incidents/pages/IncidentManagementPage").then((module) => ({ default: module.IncidentManagementPage })));
const AnalyticsPage = lazy(() => import("@/features/analytics/pages/AnalyticsPage").then((module) => ({ default: module.AnalyticsPage })));
const DetectionRulesPage = lazy(() => import("@/features/rules/pages/DetectionRulesPage").then((module) => ({ default: module.DetectionRulesPage })));
const UserManagementPage = lazy(() => import("@/features/users/pages/UserManagementPage").then((module) => ({ default: module.UserManagementPage })));
const SettingsPage = lazy(() => import("@/features/settings/pages/SettingsPage").then((module) => ({ default: module.SettingsPage })));

export function AppRouter() {
  return (
    <Suspense fallback={<div className="flex h-full items-center justify-center text-text-secondary">Loading...</div>}>
      <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/live-monitoring" element={<LiveMonitoringPage />} />
          <Route path="/upload-logs" element={<UploadLogsPage />} />
          <Route path="/threat-detection" element={<ThreatDetectionPage />} />
          <Route path="/anomaly-detection" element={<AnomalyDetectionPage />} />
          <Route path="/incidents" element={<IncidentManagementPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/detection-rules" element={<DetectionRulesPage />} />
          <Route path="/settings" element={<SettingsPage />} />

          <Route element={<AdminRoute />}>
            <Route path="/users" element={<UserManagementPage />} />
          </Route>
        </Route>
      </Route>

        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  );
}
