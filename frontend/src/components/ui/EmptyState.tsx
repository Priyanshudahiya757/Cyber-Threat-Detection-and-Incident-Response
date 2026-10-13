/**
 * src/components/ui/EmptyState.tsx
 * Shown whenever a list/table has no data — an invitation to act, per
 * the interface's own voice, not a bare "no data" dead end.
 */
import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import type { ReactNode } from "react";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="rounded-full bg-base-700 p-3">
        <Icon className="h-6 w-6 text-text-muted" aria-hidden="true" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-text-primary">{title}</p>
        {description && <p className="text-xs text-text-secondary max-w-sm">{description}</p>}
      </div>
      {action}
    </div>
  );
}
