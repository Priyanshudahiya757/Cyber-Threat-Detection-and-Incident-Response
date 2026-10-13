/**
 * src/features/auth/pages/LoginPage.tsx
 *
 * Purpose:
 *   The login screen: a branded split layout (console signature panel +
 *   form). Redirects to /dashboard if the user is already authenticated
 *   (e.g. they navigated back to /login manually with a valid session).
 */
import { Navigate } from "react-router-dom";
import { ShieldCheck, Radar, Activity } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { LoginForm } from "../components/LoginForm";

export function LoginPage() {
  const { isAuthenticated, isInitializing } = useAuth();

  if (!isInitializing && isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[1.1fr_1fr]">
      {/* Signature panel — the grid-fade texture + live pulse is the one
          bold visual element; everything else on this page stays quiet. */}
      <div className="relative hidden overflow-hidden bg-base-950 lg:flex lg:flex-col lg:justify-between lg:p-12 bg-grid-fade">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="h-6 w-6 text-accent-cyan" aria-hidden="true" />
          <span className="font-mono text-lg font-semibold tracking-tight text-text-primary">
            SentinelGrid
          </span>
        </div>

        <div className="max-w-md space-y-6">
          <div className="flex items-center gap-2 text-2xs uppercase tracking-widest text-accent-cyan">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping-slow rounded-full bg-accent-cyan opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent-cyan" />
            </span>
            Detection engines live
          </div>
          <h1 className="text-3xl font-semibold leading-tight text-text-primary">
            Unified visibility across every log source, correlated in real time.
          </h1>
          <p className="text-sm leading-relaxed text-text-secondary">
            Rule-based and AI-driven detection running side by side — Windows, Linux, firewall, and
            web server telemetry, normalized into one investigation surface.
          </p>
        </div>

        <div className="flex gap-6 font-data text-xs text-text-muted">
          <div className="flex items-center gap-1.5">
            <Radar className="h-3.5 w-3.5 text-accent-cyan" /> 8 rule detections
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5 text-accent-cyan" /> Isolation Forest anomaly engine
          </div>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex items-center justify-center bg-base-900 px-6 py-12">
        <div className="w-full max-w-sm space-y-8">
          <div className="space-y-1.5 lg:hidden">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-accent-cyan" />
              <span className="font-mono text-base font-semibold text-text-primary">SentinelGrid</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <h2 className="text-xl font-semibold text-text-primary">Sign in to the console</h2>
            <p className="text-sm text-text-secondary">Enter your analyst or administrator credentials.</p>
          </div>

          <LoginForm />
        </div>
      </div>
    </div>
  );
}
