/**
 * User Management (admin only) — create accounts, change roles, disable
 * accounts and reset passwords. Accounts are disabled rather than
 * deleted so incident timelines keep pointing at a real user.
 */
import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, UserPlus } from "lucide-react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { userService } from "@/services/userService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime } from "@/lib/format";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Input,
  Notice,
  Select,
  Spinner,
  type NoticeMessage,
} from "@/components/ui";
import { ROLE_LABELS, type UserCreateRequest, type UserRole, type UserUpdateRequest } from "@/types";

const PASSWORD_HINT = "At least 8 characters, with a letter and a digit.";
const EMPTY_FORM: UserCreateRequest = { username: "", email: "", password: "", role: "soc_analyst" };

export function UserManagementPage() {
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<UserCreateRequest>(EMPTY_FORM);
  const [notice, setNotice] = useState<NoticeMessage | null>(null);
  const [resetTarget, setResetTarget] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState("");

  const usersQuery = useQuery({ queryKey: ["users"], queryFn: userService.list });

  const fail = (error: unknown) => setNotice({ tone: "error", text: getErrorMessage(error) });
  const succeed = (text: string) => {
    setNotice({ tone: "success", text });
    queryClient.invalidateQueries({ queryKey: ["users"] });
  };

  const createMutation = useMutation({
    mutationFn: () => userService.create(form),
    onSuccess: (created) => {
      succeed(`User "${created.username}" created.`);
      setForm(EMPTY_FORM);
    },
    onError: fail,
  });

  const updateMutation = useMutation({
    mutationFn: ({ username, changes }: { username: string; changes: UserUpdateRequest }) =>
      userService.update(username, changes),
    onSuccess: (updated) => succeed(`User "${updated.username}" updated.`),
    onError: fail,
  });

  const resetMutation = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      userService.resetPassword(username, password),
    onSuccess: (_, { username }) => {
      succeed(`Password reset for "${username}". Their existing sessions were signed out.`);
      setResetTarget(null);
      setNewPassword("");
    },
    onError: fail,
  });

  const handleCreate = (event: FormEvent) => {
    event.preventDefault();
    createMutation.mutate();
  };

  const handleReset = (event: FormEvent) => {
    event.preventDefault();
    if (resetTarget) resetMutation.mutate({ username: resetTarget, password: newPassword });
  };

  const users = usersQuery.data ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">User Management</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Create analyst and admin accounts, change roles, and disable access.
        </p>
      </div>

      {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}

      <Card>
        <CardHeader>
          <CardTitle>Accounts ({users.length})</CardTitle>
        </CardHeader>
        <CardBody className="overflow-x-auto">
          {usersQuery.isLoading ? (
            <div className="flex h-32 items-center justify-center">
              <Spinner />
            </div>
          ) : usersQuery.isError ? (
            <Notice tone="error">{getErrorMessage(usersQuery.error, "Could not load users.")}</Notice>
          ) : (
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="text-2xs uppercase text-text-muted">
                <tr>
                  <th className="pb-3 pr-3">Username</th>
                  <th className="pb-3 pr-3">Email</th>
                  <th className="pb-3 pr-3">Role</th>
                  <th className="pb-3 pr-3">Status</th>
                  <th className="pb-3 pr-3">Last login</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {users.map((account) => {
                  const isSelf = account.username === currentUser?.username;
                  return (
                    <tr key={account.id}>
                      <td className="py-2.5 pr-3 font-data text-text-primary">
                        {account.username}
                        {isSelf && <span className="ml-2 text-2xs text-text-muted">(you)</span>}
                      </td>
                      <td className="py-2.5 pr-3 text-text-secondary">{account.email}</td>
                      <td className="py-2.5 pr-3">
                        <Select
                          aria-label={`Role of ${account.username}`}
                          className="h-8"
                          value={account.role}
                          disabled={isSelf || updateMutation.isPending}
                          onChange={(event) =>
                            updateMutation.mutate({
                              username: account.username,
                              changes: { role: event.target.value as UserRole },
                            })
                          }
                        >
                          {Object.entries(ROLE_LABELS).map(([value, label]) => (
                            <option key={value} value={value}>
                              {label}
                            </option>
                          ))}
                        </Select>
                      </td>
                      <td className="py-2.5 pr-3">
                        <Badge tone={account.is_active ? "success" : "neutral"}>
                          {account.is_active ? "Active" : "Disabled"}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-3 font-data text-text-secondary">
                        {account.last_login ? formatDateTime(account.last_login) : "Never"}
                      </td>
                      <td className="py-2.5">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setResetTarget(account.username);
                              setNewPassword("");
                            }}
                          >
                            <KeyRound className="h-3.5 w-3.5" />
                            Reset password
                          </Button>
                          <Button
                            size="sm"
                            variant={account.is_active ? "danger" : "outline"}
                            disabled={isSelf || updateMutation.isPending}
                            title={isSelf ? "You cannot disable your own account" : undefined}
                            onClick={() =>
                              updateMutation.mutate({
                                username: account.username,
                                changes: { is_active: !account.is_active },
                              })
                            }
                          >
                            {account.is_active ? "Disable" : "Enable"}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </CardBody>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Create user</CardTitle>
          </CardHeader>
          <CardBody>
            <form onSubmit={handleCreate} className="space-y-4">
              <Input
                label="Username"
                name="new-username"
                autoComplete="off"
                value={form.username}
                onChange={(event) => setForm({ ...form, username: event.target.value })}
              />
              <Input
                label="Email"
                name="new-email"
                type="email"
                autoComplete="off"
                value={form.email}
                onChange={(event) => setForm({ ...form, email: event.target.value })}
              />
              <div>
                <Input
                  label="Password"
                  name="new-password"
                  type="password"
                  autoComplete="new-password"
                  value={form.password}
                  onChange={(event) => setForm({ ...form, password: event.target.value })}
                />
                <p className="mt-1 text-xs text-text-muted">{PASSWORD_HINT}</p>
              </div>
              <Select
                label="Role"
                name="new-role"
                value={form.role}
                onChange={(event) => setForm({ ...form, role: event.target.value as UserRole })}
              >
                {Object.entries(ROLE_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
              <Button
                type="submit"
                isLoading={createMutation.isPending}
                disabled={!form.username || !form.email || !form.password}
              >
                <UserPlus className="h-4 w-4" />
                Create user
              </Button>
            </form>
          </CardBody>
        </Card>

        {resetTarget && (
          <Card>
            <CardHeader>
              <CardTitle>
                Reset password for <span className="font-data text-accent-cyan">{resetTarget}</span>
              </CardTitle>
            </CardHeader>
            <CardBody>
              <form onSubmit={handleReset} className="space-y-4">
                <div>
                  <Input
                    label="New password"
                    name="reset-password"
                    type="password"
                    autoComplete="new-password"
                    autoFocus
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                  />
                  <p className="mt-1 text-xs text-text-muted">{PASSWORD_HINT}</p>
                </div>
                <div className="flex gap-2">
                  <Button type="submit" isLoading={resetMutation.isPending} disabled={!newPassword}>
                    Set password
                  </Button>
                  <Button type="button" variant="ghost" onClick={() => setResetTarget(null)}>
                    Cancel
                  </Button>
                </div>
              </form>
            </CardBody>
          </Card>
        )}
      </div>
    </div>
  );
}
