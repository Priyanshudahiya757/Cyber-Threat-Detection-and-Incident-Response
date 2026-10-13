/**
 * src/lib/format.ts
 * Display formatting shared by every table and timeline.
 */
import { format, parseISO } from "date-fns";

const PLACEHOLDER = "—";

function formatIso(value: string | null | undefined, pattern: string): string {
  if (!value) return PLACEHOLDER;
  try {
    return format(parseISO(value), pattern);
  } catch {
    return PLACEHOLDER;
  }
}

/** e.g. "Jul 19 09:12:03", in the viewer's local time zone. */
export function formatDateTime(value: string | null | undefined): string {
  return formatIso(value, "MMM d HH:mm:ss");
}

/** e.g. "09:00" — for chart axes. */
export function formatHour(value: string | null | undefined): string {
  return formatIso(value, "HH:mm");
}

const ACRONYMS: Record<string, string> = { ssh: "SSH", sql: "SQL", xss: "XSS", ip: "IP", ips: "IPs", http: "HTTP" };

/** "ssh_brute_force" -> "SSH Brute Force" */
export function humanize(identifier: string): string {
  return identifier
    .split("_")
    .map((word) => ACRONYMS[word] ?? word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
