/**
 * src/routes/AdminRoute.tsx
 *
 * Purpose:
 *   Nested guard for admin-only pages (User Management). Sits inside
 *   ProtectedRoute, so it can assume the user is already authenticated
 *   and only needs to check role. Redirects non-admins to /dashboard
 *   rather than /login — they ARE authenticated, just not authorized.
 */
import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "@/features/auth/hooks/useAuth";

export function AdminRoute() {
  const { user } = useAuth();

  if (user?.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
}
