/**
 * src/components/layout/navConfig.ts
 *
 * Purpose:
 *   Single source of truth for sidebar navigation — route path, label,
 *   icon, and optional role restriction. AppRouter.tsx's route
 *   definitions and Sidebar.tsx's rendered links both stay in sync
 *   because both are driven by this list rather than hand-duplicated.
 */
import type { LucideIcon } from "lucide-react";
import {
  LayoutDashboard,
  Radio,
  UploadCloud,
  ShieldAlert,
  BrainCircuit,
  FolderKanban,
  BarChart3,
  ListChecks,
  Users,
  Settings,
} from "lucide-react";
import type { UserRole } from "@/types";

export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  /** If set, only these roles see this item. Omitted = visible to all authenticated roles. */
  restrictedTo?: UserRole[];
}

export const NAV_ITEMS: NavItem[] = [
  { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { path: "/live-monitoring", label: "Live Monitoring", icon: Radio },
  { path: "/upload-logs", label: "Upload Logs", icon: UploadCloud },
  { path: "/threat-detection", label: "Threat Detection", icon: ShieldAlert },
  { path: "/anomaly-detection", label: "AI Anomaly Detection", icon: BrainCircuit },
  { path: "/incidents", label: "Incident Management", icon: FolderKanban },
  { path: "/analytics", label: "Analytics", icon: BarChart3 },
  { path: "/detection-rules", label: "Detection Rules", icon: ListChecks },
  { path: "/users", label: "User Management", icon: Users, restrictedTo: ["admin"] },
  { path: "/settings", label: "Settings", icon: Settings },
];
