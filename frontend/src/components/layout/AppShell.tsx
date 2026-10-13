/**
 * src/components/layout/AppShell.tsx
 *
 * Purpose:
 *   The authenticated app's persistent layout: fixed sidebar + topbar,
 *   scrollable content area. Rendered once by ProtectedRoute and wraps
 *   every authenticated page via <Outlet />, so Sidebar/Topbar never
 *   remount on navigation — only the page content below them does.
 */
import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export function AppShell() {
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  return (
    <div className="flex h-screen overflow-hidden bg-base-900">
      <Sidebar isMobileOpen={isMobileSidebarOpen} onMobileClose={() => setIsMobileSidebarOpen(false)} />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Topbar onMenuClick={() => setIsMobileSidebarOpen(true)} />
        <main className="flex-1 overflow-y-auto px-4 py-5 sm:px-6 sm:py-6">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
