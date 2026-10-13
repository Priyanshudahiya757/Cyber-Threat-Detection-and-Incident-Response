/**
 * src/routes/ProtectedRoute.tsx
 *
 * Purpose:
 *   Gates the entire authenticated app behind a valid session. Shows a
 *   full-screen spinner during AuthContext's initial "is there a stored
 *   token?" check, rather than flashing a redirect to /login for users
 *   who are actually already signed in.
 */
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { Spinner } from "@/components/ui";

export function ProtectedRoute() {
  const { isAuthenticated, isInitializing } = useAuth();
  const location = useLocation();

  if (isInitializing) {
    return (
      <div className="flex h-screen items-center justify-center bg-base-900">
        <Spinner size="lg" label="Loading session…" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <Outlet />;
}
