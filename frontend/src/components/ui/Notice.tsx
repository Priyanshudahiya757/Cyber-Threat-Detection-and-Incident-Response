/**
 * src/components/ui/Notice.tsx
 * Inline result banner shown after an action: success, error, or neutral info.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

type NoticeTone = "success" | "error" | "info";

const toneClasses: Record<NoticeTone, string> = {
  success: "border-severity-success/30 bg-severity-success-dim/40 text-severity-success",
  error: "border-severity-critical/30 bg-severity-critical-dim/40 text-severity-critical",
  info: "border-accent-cyan/30 bg-accent-cyan/10 text-accent-cyan",
};

export interface NoticeMessage {
  tone: NoticeTone;
  text: string;
}

interface NoticeProps {
  tone: NoticeTone;
  children: ReactNode;
  className?: string;
}

export function Notice({ tone, children, className }: NoticeProps) {
  return (
    <p
      role={tone === "error" ? "alert" : "status"}
      className={cn("rounded-md border px-3 py-2 text-sm", toneClasses[tone], className)}
    >
      {children}
    </p>
  );
}
