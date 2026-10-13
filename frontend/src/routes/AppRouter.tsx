/**
 * src/routes/AppRouter.tsx
 *
 * Purpose:
 *   Declares every route in the app. Paths are driven by the same
 *   NAV_ITEMS list Sidebar.tsx renders from, so the two structures can't
 *   silently drift apart (a nav link pointing at a route that doesn't exist).
 */
import { Routes, Route, Navigate } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { ProtectedRoute } from "./ProtectedRoute";
import { AdminRoute } from "./AdminRoute";
import { NotFoundPage } from "./NotFoundPage";

import { LoginPage } from "@/features/auth/pages/LoginPage";
import { DashboardPage } from "@/features/dashboard/pages/DashboardPage";
import { LiveMonitoringPage } from "@/features/monitoring/pages/LiveMonitoringPage";
import { UploadLogsPage } from "@/features/logs/pages/UploadLogsPage";
import { ThreatDetectionPage } from "@/features/detections/pages/ThreatDetectionPage";
import { AnomalyDetectionPage } from "@/features/anomalies/pages/AnomalyDetectionPage";
import { IncidentManagementPage } from "@/features/incidents/pages/IncidentManagementPage";
import { AnalyticsPage } from "@/features/analytics/pages/AnalyticsPage";
import { DetectionRulesPage } from "@/features/rules/pages/DetectionRulesPage";
import { UserManagementPage } from "@/features/users/pages/UserManagementPage";
import { SettingsPage } from "@/features/settings/pages/SettingsPage";

export function AppRouter() {
  return (
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
  );
}
