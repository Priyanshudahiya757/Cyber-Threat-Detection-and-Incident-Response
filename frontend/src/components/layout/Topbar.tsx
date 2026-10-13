/**
 * src/components/layout/Topbar.tsx
 *
 * Purpose:
 *   Page title (derived from the current route via navConfig), global
 *   search stub, notification bell, and the user menu (profile link +
 *   logout). The user menu is the only piece with real behavior in
 *   Module 1 — search/notifications are wired to obvious future
 *   endpoints but intentionally inert until later modules.
 */
import { useState, useRef, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Bell, ChevronDown, LogOut, Menu, Search, User as UserIcon } from "lucide-react";
import { NAV_ITEMS } from "./navConfig";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { cn } from "@/lib/cn";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  const currentPage = NAV_ITEMS.find((item) => location.pathname.startsWith(item.path));

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <header className="flex h-16 items-center justify-between border-b border-border bg-base-900 px-4 sm:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onMenuClick}
          className="rounded-md p-1.5 text-text-secondary hover:bg-base-700 hover:text-text-primary lg:hidden"
          aria-label="Open navigation"
        >
          <Menu className="h-5 w-5" />
        </button>
        <h1 className="text-base font-semibold text-text-primary">{currentPage?.label ?? "SentinelGrid"}</h1>
      </div>
      <div className="flex items-center gap-4">
        <div className="relative hidden md:block">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            type="search"
            placeholder="Search logs, incidents, IPs…"
            className="h-9 w-72 rounded-md border border-border bg-base-800 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus-visible:ring-2 focus-visible:ring-accent-cyan"
          />
        </div>

        <button
          type="button"
          className="relative rounded-md p-2 text-text-secondary hover:bg-base-700 hover:text-text-primary"
          aria-label="Notifications"
        >
          <Bell className="h-5 w-5" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-severity-critical" />
        </button>

        <div className="relative" ref={menuRef}>
          <button
            type="button"
            onClick={() => setMenuOpen((v) => !v)}
            className="flex items-center gap-2 rounded-md py-1.5 pl-1.5 pr-2 hover:bg-base-700"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
          >
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-accent-blue/20 text-accent-cyan">
              <UserIcon className="h-4 w-4" />
            </div>
            <div className="hidden text-left sm:block">
              <p className="text-xs font-medium leading-tight text-text-primary">{user?.username}</p>
              <p className="text-2xs capitalize leading-tight text-text-muted">
                {user?.role.replace("_", " ")}
              </p>
            </div>
            <ChevronDown className={cn("h-3.5 w-3.5 text-text-muted transition-transform", menuOpen && "rotate-180")} />
          </button>

          {menuOpen && (
            <div
              role="menu"
              className="absolute right-0 top-full z-20 mt-2 w-48 overflow-hidden rounded-md border border-border bg-base-700 shadow-panel"
            >
              <button
                role="menuitem"
                onClick={() => {
                  setMenuOpen(false);
                  navigate("/settings");
                }}
                className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm text-text-secondary hover:bg-base-600 hover:text-text-primary"
              >
                <UserIcon className="h-4 w-4" /> Profile settings
              </button>
              <button
                role="menuitem"
                onClick={handleLogout}
                className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm text-severity-critical hover:bg-severity-critical-dim/30"
              >
                <LogOut className="h-4 w-4" /> Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
