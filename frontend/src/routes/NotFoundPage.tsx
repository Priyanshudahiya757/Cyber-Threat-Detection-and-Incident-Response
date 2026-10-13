import { Link } from "react-router-dom";
import { SearchX } from "lucide-react";
import { Button } from "@/components/ui";

export function NotFoundPage() {
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-4 bg-base-900 text-center">
      <SearchX className="h-10 w-10 text-text-muted" aria-hidden="true" />
      <div className="space-y-1">
        <p className="font-mono text-2xl font-semibold text-text-primary">404</p>
        <p className="text-sm text-text-secondary">This route doesn't exist in the console.</p>
      </div>
      <Link to="/dashboard">
        <Button variant="outline" size="sm">
          Back to dashboard
        </Button>
      </Link>
    </div>
  );
}
