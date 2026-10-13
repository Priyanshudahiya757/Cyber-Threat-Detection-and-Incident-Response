/**
 * src/components/layout/Topbar.tsx
 *
 * Purpose:
 *   Page title (derived from the current route via navConfig), log
 *   search, the unacknowledged-alert indicator, and the user menu.
 *   Search hands the query to the Live Monitoring page; the bell opens
 *   the alert list on the Threat Detection page.
 */
import { useState, useRef, useEffect, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Bell, ChevronDown, LogOut, Menu, Search, User as UserIcon } from "lucide-react";
import { NAV_ITEMS } from "./navConfig";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { alertService } from "@/services/alertService";
import { cn } from "@/lib/cn";
import { ROLE_LABELS } from "@/types";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [search, setSearch] = useState("");
  const menuRef = useRef<HTMLDivElement>(null);

  const currentPage = NAV_ITEMS.find((item) => location.pathname.startsWith(item.path));

  const { data: openAlerts } = useQuery({
    queryKey: ["alerts", "unacknowledged-count"],
    queryFn: () => alertService.list({ acknowledged: false, limit: 1 }),
    refetchInterval: 15_000,
  });
  const unacknowledged = openAlerts?.unacknowledged_total ?? 0;

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

  const handleSearch = (event: FormEvent) => {
    event.preventDefault();
    const query = search.trim();
    if (!query) return;
    navigate(`/live-monitoring?q=${encodeURIComponent(query)}`);
    setSearch("");
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
        <form onSubmit={handleSearch} className="relative hidden md:block" role="search">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search logs…"
            aria-label="Search logs"
            className="h-9 w-72 rounded-md border border-border bg-base-800 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus-visible:ring-2 focus-visible:ring-accent-cyan"
          />
        </form>

        <button
          type="button"
          onClick={() => navigate("/threat-detection")}
          className="relative rounded-md p-2 text-text-secondary hover:bg-base-700 hover:text-text-primary"
          aria-label={
            unacknowledged > 0 ? `${unacknowledged} unacknowledged alerts` : "No unacknowledged alerts"
          }
        >
          <Bell className="h-5 w-5" />
          {unacknowledged > 0 && (
            <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-severity-critical px-1 font-data text-[10px] font-semibold leading-none text-white">
              {unacknowledged > 99 ? "99+" : unacknowledged}
            </span>
          )}
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
              <p className="text-2xs leading-tight text-text-muted">{user && ROLE_LABELS[user.role]}</p>
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
