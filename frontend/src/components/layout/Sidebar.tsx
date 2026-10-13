/**
 * src/components/layout/Sidebar.tsx
 *
 * Purpose:
 *   Primary navigation. Active-item treatment is a left cyan glow bar
 *   (not a filled pill) — the deliberate "terminal cursor / active
 *   process" signature referenced in the design token comments in
 *   tailwind.config.ts, chosen because it reads as status indication
 *   rather than decoration, fitting a console the brief asks to feel
 *   like an enterprise SIEM.
 */
import { NavLink } from "react-router-dom";
import { ShieldCheck, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { NAV_ITEMS } from "./navConfig";
import { useAuth } from "@/features/auth/hooks/useAuth";

interface SidebarProps {
  /** Controls off-canvas visibility on small screens (<lg). Always visible at lg+. */
  isMobileOpen: boolean;
  onMobileClose: () => void;
}

export function Sidebar({ isMobileOpen, onMobileClose }: SidebarProps) {
  const { user } = useAuth();

  const visibleItems = NAV_ITEMS.filter(
    (item) => !item.restrictedTo || (user && item.restrictedTo.includes(user.role))
  );

  return (
    <>
      {/* Mobile scrim */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={onMobileClose}
          aria-hidden="true"
        />
      )}

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-border bg-base-950 transition-transform lg:static lg:translate-x-0",
          isMobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex h-16 items-center justify-between gap-2.5 border-b border-border px-5">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="h-5 w-5 text-accent-cyan" aria-hidden="true" />
            <span className="font-mono text-sm font-semibold tracking-tight text-text-primary">
              SentinelGrid
            </span>
          </div>
          <button
            type="button"
            onClick={onMobileClose}
            className="rounded-md p-1 text-text-muted hover:bg-base-700 lg:hidden"
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4 scrollbar-none" aria-label="Primary">
          {visibleItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={onMobileClose}
              className={({ isActive }) =>
                cn(
                  "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent-cyan/10 text-text-primary"
                    : "text-text-secondary hover:bg-base-700 hover:text-text-primary"
                )
              }
            >
              {({ isActive }) => (
                <>
                  <span
                    className={cn(
                      "absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r bg-accent-cyan transition-opacity",
                      isActive ? "opacity-100" : "opacity-0"
                    )}
                    aria-hidden="true"
                  />
                  <item.icon
                    className={cn("h-4 w-4 shrink-0", isActive ? "text-accent-cyan" : "text-text-muted")}
                    aria-hidden="true"
                  />
                  <span className="truncate">{item.label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-border px-5 py-4">
          <div className="flex items-center gap-2 font-data text-2xs text-text-muted">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping-slow rounded-full bg-severity-success opacity-60" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-severity-success" />
            </span>
            v0.1.0 · connected
          </div>
        </div>
      </aside>
    </>
  );
}
