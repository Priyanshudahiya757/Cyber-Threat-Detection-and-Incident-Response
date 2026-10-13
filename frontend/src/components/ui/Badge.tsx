/**
 * src/components/ui/Badge.tsx
 *
 * Purpose:
 *   Renders severity levels and statuses with the exact semantic colors
 *   the brief specifies (red=critical, orange=warning, green=healthy).
 *   Every table/card that shows a Severity anywhere in the app should
 *   route through this component rather than reimplementing the color
 *   mapping — keeps severity color meaning consistent app-wide.
 */
import type { HTMLAttributes } from "react";
import { cn } from "@/lib/cn";
import type { BadgeTone } from "./badgeUtils";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone: BadgeTone;
}

const toneClasses: Record<BadgeTone, string> = {
  critical: "bg-severity-critical-dim text-severity-critical border-severity-critical/30",
  high: "bg-severity-critical-dim/70 text-severity-high border-severity-high/30",
  warning: "bg-severity-warning-dim text-severity-warning border-severity-warning/30",
  medium: "bg-severity-warning-dim/70 text-severity-medium border-severity-medium/30",
  low: "bg-accent-blue/10 text-accent-blue border-accent-blue/30",
  success: "bg-severity-success-dim text-severity-success border-severity-success/30",
  info: "bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30",
  neutral: "bg-base-600 text-text-secondary border-border",
};

const toneLabels: Record<BadgeTone, string> = {
  critical: "Critical",
  high: "High",
  warning: "Warning",
  medium: "Medium",
  low: "Low",
  success: "Healthy",
  info: "Info",
  neutral: "Unknown",
};

export function Badge({ tone, className, children, ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-2xs font-semibold uppercase tracking-wide",
        toneClasses[tone],
        className
      )}
      {...props}
    >
      {children ?? toneLabels[tone]}
    </span>
  );
}
