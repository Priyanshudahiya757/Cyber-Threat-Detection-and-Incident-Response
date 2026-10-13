/**
 * src/lib/apiError.ts
 * Turns whatever a failed request threw into one sentence a user can read.
 */
import { isAxiosError } from "axios";

interface ValidationIssue {
  loc?: (string | number)[];
  msg?: string;
}

export function getErrorMessage(error: unknown, fallback = "Something went wrong. Please try again."): string {
  if (!isAxiosError(error)) {
    return error instanceof Error && error.message ? error.message : fallback;
  }
  if (!error.response) {
    return "Can't reach the server. Check that the backend is running.";
  }

  const detail: unknown = error.response.data?.detail;
  if (typeof detail === "string") return detail;

  // FastAPI reports request-validation failures as a list of issues.
  if (Array.isArray(detail) && detail.length > 0) {
    const issue = detail[0] as ValidationIssue;
    const field = issue.loc?.[issue.loc.length - 1];
    const message = (issue.msg ?? "Invalid value").replace(/^Value error, /, "");
    return typeof field === "string" && field !== "body" ? `${field}: ${message}` : message;
  }
  return fallback;
}
