/**
 * src/components/common/ComingSoonPage.tsx
 *
 * Purpose:
 *   Placeholder rendered by feature pages not yet built (this is Module
 *   1: infrastructure + auth + shell only). Each feature page file
 *   (e.g. src/features/dashboard/pages/DashboardPage.tsx) is a real,
 *   permanent file in the final folder structure — only its contents
 *   get replaced in a later module, so routing/imports never change.
 */
import type { LucideIcon } from "lucide-react";
import { Construction } from "lucide-react";
import { Card, CardBody } from "@/components/ui";

interface ComingSoonPageProps {
  title: string;
  icon: LucideIcon;
  moduleLabel: string;
  summary: string;
}

export function ComingSoonPage({ title, icon: Icon, moduleLabel, summary }: ComingSoonPageProps) {
  return (
    <div className="mx-auto flex max-w-2xl flex-col items-center gap-6 py-16 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-full bg-accent-blue/10">
        <Icon className="h-7 w-7 text-accent-cyan" aria-hidden="true" />
      </div>
      <div className="space-y-2">
        <h2 className="text-xl font-semibold text-text-primary">{title}</h2>
        <p className="text-sm text-text-secondary">{summary}</p>
      </div>
      <Card className="w-full">
        <CardBody className="flex items-center gap-3 text-left">
          <Construction className="h-5 w-5 shrink-0 text-severity-warning" aria-hidden="true" />
          <p className="text-sm text-text-secondary">
            <span className="font-medium text-text-primary">{moduleLabel}</span> — this page's layout,
            service layer, and components are built in a following module, per the project's incremental
            build plan. Navigation, auth, and the app shell around it are fully live now.
          </p>
        </CardBody>
      </Card>
    </div>
  );
}
