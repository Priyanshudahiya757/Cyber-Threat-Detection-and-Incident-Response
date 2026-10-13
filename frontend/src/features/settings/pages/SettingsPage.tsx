/**
 * Settings — own profile and password, platform health, and where
 * alerts are delivered.
 */
import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { alertService } from "@/services/alertService";
import { fetchSystemHealth, HEALTH_QUERY_KEY } from "@/services/healthService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime, humanize } from "@/lib/format";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Input,
  Notice,
  Spinner,
  type NoticeMessage,
} from "@/components/ui";
import { ROLE_LABELS, type AlertChannelResult } from "@/types";

function ProfileRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-text-muted">{label}</span>
      <span className="text-right text-text-primary">{children}</span>
    </div>
  );
}

function ChangePasswordCard() {
  const { changePassword } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [notice, setNotice] = useState<NoticeMessage | null>(null);

  const mismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;

  const mutation = useMutation({
    mutationFn: () => changePassword({ current_password: currentPassword, new_password: newPassword }),
    onSuccess: () => {
      setNotice({ tone: "success", text: "Password changed. Other sessions were signed out." });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    },
    onError: (error) => setNotice({ tone: "error", text: getErrorMessage(error) }),
  });

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    mutation.mutate();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
      </CardHeader>
      <CardBody>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Current password"
            name="current-password"
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
          />
          <Input
            label="New password"
            name="new-password"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
          <Input
            label="Confirm new password"
            name="confirm-password"
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            error={mismatch ? "Passwords do not match" : undefined}
          />
          <p className="text-xs text-text-muted">At least 8 characters, with a letter and a digit.</p>
          {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}
          <Button
            type="submit"
            isLoading={mutation.isPending}
            disabled={!currentPassword || !newPassword || newPassword !== confirmPassword}
          >
            Update password
          </Button>
        </form>
      </CardBody>
    </Card>
  );
}

function AlertChannelsCard({ isAdmin }: { isAdmin: boolean }) {
  const [results, setResults] = useState<AlertChannelResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const channelsQuery = useQuery({ queryKey: ["alerts", "channels"], queryFn: alertService.channels });
  const channels = channelsQuery.data ?? [];
  const anyConfigured = channels.some((channel) => channel.configured);

  const testMutation = useMutation({
    mutationFn: alertService.sendTest,
    onSuccess: (data) => {
      setError(null);
      setResults(data);
    },
    onError: (err) => {
      setResults(null);
      setError(getErrorMessage(err));
    },
  });

  const outcomeOf = (channel: string) => results?.find((result) => result.channel === channel);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alert delivery</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4 text-sm">
        <p className="text-text-secondary">
          High and critical alerts are sent to every configured channel. Channels are configured with
          environment variables in <span className="font-data text-text-primary">backend/.env</span>.
        </p>

        {channelsQuery.isLoading ? (
          <Spinner />
        ) : (
          <ul className="space-y-2">
            {channels.map(({ channel, configured }) => {
              const outcome = outcomeOf(channel);
              return (
                <li key={channel} className="flex items-center justify-between rounded-md bg-base-700/50 px-3 py-2">
                  <span className="text-text-primary">{humanize(channel)}</span>
                  <span className="flex items-center gap-2">
                    {outcome?.delivered && <Badge tone="success">Test delivered</Badge>}
                    {outcome?.error && <Badge tone="critical">Failed: {outcome.error}</Badge>}
                    <Badge tone={configured ? "info" : "neutral"}>
                      {configured ? "Configured" : "Not configured"}
                    </Badge>
                  </span>
                </li>
              );
            })}
          </ul>
        )}

        {error && <Notice tone="error">{error}</Notice>}

        {isAdmin && (
          <Button
            variant="outline"
            onClick={() => testMutation.mutate()}
            isLoading={testMutation.isPending}
            disabled={!anyConfigured}
            title={anyConfigured ? undefined : "Configure at least one channel first"}
          >
            <Send className="h-4 w-4" />
            Send test alert
          </Button>
        )}
      </CardBody>
    </Card>
  );
}

function SystemHealthCard() {
  const healthQuery = useQuery({
    queryKey: HEALTH_QUERY_KEY,
    queryFn: fetchSystemHealth,
    retry: false,
    refetchInterval: 30_000,
  });
  const health = healthQuery.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle>System health</CardTitle>
      </CardHeader>
      <CardBody>
        {healthQuery.isLoading ? (
          <Spinner />
        ) : !health ? (
          <Notice tone="error">The backend could not be reached.</Notice>
        ) : (
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-md bg-base-700/50 px-4 py-3">
              <p className="mb-1 text-2xs uppercase text-text-muted">Platform v{health.version}</p>
              <Badge tone={health.status === "ready" ? "success" : "warning"}>{health.status}</Badge>
            </div>
            {Object.entries(health.checks).map(([name, value]) => (
              <div key={name} className="rounded-md bg-base-700/50 px-4 py-3">
                <p className="mb-1 text-2xs uppercase text-text-muted">{name}</p>
                <Badge tone={value === "ok" ? "success" : "critical"}>{value}</Badge>
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export function SettingsPage() {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Settings</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Your account, platform health, and alert delivery channels.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardBody className="space-y-3 text-sm">
            <ProfileRow label="Username">
              <span className="font-data">{user.username}</span>
            </ProfileRow>
            <ProfileRow label="Email">{user.email}</ProfileRow>
            <ProfileRow label="Role">
              <Badge tone={user.role === "admin" ? "info" : "neutral"}>{ROLE_LABELS[user.role]}</Badge>
            </ProfileRow>
            <ProfileRow label="Member since">
              <span className="font-data">{formatDateTime(user.created_at)}</span>
            </ProfileRow>
          </CardBody>
        </Card>

        <ChangePasswordCard />
        <AlertChannelsCard isAdmin={user.role === "admin"} />
        <SystemHealthCard />
      </div>
    </div>
  );
}
