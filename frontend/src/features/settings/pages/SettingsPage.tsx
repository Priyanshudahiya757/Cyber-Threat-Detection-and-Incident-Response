/**
 * Settings — profile / session info and API connectivity status.
 */
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { env } from "@/config/env";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";

export function SettingsPage() {
  const { user } = useAuth();

  const healthQuery = useQuery({
    queryKey: ["health", "ready"],
    queryFn: async () => {
      const res = await fetch("/health/ready");
      if (!res.ok && res.status !== 503) throw new Error("Health check failed");
      return (await res.json()) as { status: string; checks: Record<string, string> };
    },
    retry: false,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Settings</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Session profile and platform connectivity for this SOC console.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardBody className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-text-muted">Username</span>
              <span className="font-data text-text-primary">{user?.username}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Email</span>
              <span className="text-text-primary">{user?.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Role</span>
              <Badge tone={user?.role === "admin" ? "info" : "neutral"}>{user?.role}</Badge>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>API configuration</CardTitle>
          </CardHeader>
          <CardBody className="space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <span className="text-text-muted">API base</span>
              <span className="font-data text-accent-cyan">{env.apiBaseUrl}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Demo mode mocks</span>
              <span>{env.useMocksForUnimplemented ? "on" : "off (live API)"}</span>
            </div>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>System health</CardTitle>
          </CardHeader>
          <CardBody>
            {healthQuery.isLoading ? (
              <Spinner />
            ) : (
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-md bg-base-700/50 px-4 py-3">
                  <p className="text-2xs uppercase text-text-muted">Overall</p>
                  <Badge tone={healthQuery.data?.status === "ready" ? "success" : "warning"}>
                    {healthQuery.data?.status ?? "unknown"}
                  </Badge>
                </div>
                {Object.entries(healthQuery.data?.checks ?? {}).map(([name, value]) => (
                  <div key={name} className="rounded-md bg-base-700/50 px-4 py-3">
                    <p className="text-2xs uppercase text-text-muted">{name}</p>
                    <Badge tone={value === "ok" ? "success" : "warning"}>{value}</Badge>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
