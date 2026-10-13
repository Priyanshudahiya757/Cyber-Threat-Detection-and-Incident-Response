/**
 * src/components/common/ErrorBoundary.tsx
 *
 * Purpose:
 *   Catches render-time errors in its subtree so one broken page (a bad
 *   chart render, a malformed API response the component didn't guard
 *   against) doesn't take down the entire console. Wrapped around the
 *   route outlet in AppShell, so navigating to a different page recovers
 *   automatically even if the current one crashed.
 */
import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // In production this is where an error-reporting service call would
    // go; for now, a loud console error keeps the failure visible during
    // development and demos without silently swallowing it.
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-severity-critical/30 bg-severity-critical-dim/20 px-6 py-16 text-center">
          <AlertTriangle className="h-8 w-8 text-severity-critical" aria-hidden="true" />
          <div className="space-y-1">
            <p className="text-sm font-semibold text-text-primary">This page hit an unexpected error</p>
            <p className="text-xs text-text-secondary max-w-md">
              {this.state.error?.message ?? "Something went wrong while rendering this view."}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={this.handleReset}>
            Try again
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}
