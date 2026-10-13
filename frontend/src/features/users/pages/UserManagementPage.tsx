/**
 * User Management — register new SOC users (admin only).
 */
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

export function UserManagementPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"admin" | "soc_analyst">("soc_analyst");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const registerMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.post(ENDPOINTS.auth.register, {
        username,
        email,
        password,
        role,
      });
      return res.data;
    },
    onSuccess: () => {
      setError(null);
      setMessage(`User "${username}" created successfully.`);
      setUsername("");
      setEmail("");
      setPassword("");
    },
    onError: (err: unknown) => {
      setMessage(null);
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Registration failed";
      setError(String(detail));
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">User Management</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Create analyst and admin accounts for the SOC dashboard.
        </p>
      </div>

      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle>Register user</CardTitle>
        </CardHeader>
        <CardBody className="space-y-4">
          <Input label="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
          <Input
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div>
            <label className="mb-1.5 block text-sm font-medium text-text-secondary">Role</label>
            <select
              className="h-10 w-full rounded-md border border-border bg-base-800 px-3 text-sm"
              value={role}
              onChange={(e) => setRole(e.target.value as "admin" | "soc_analyst")}
            >
              <option value="soc_analyst">SOC Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          {message && (
            <p className="text-sm text-severity-success">{message}</p>
          )}
          {error && <p className="text-sm text-severity-critical">{error}</p>}

          <Button
            onClick={() => registerMutation.mutate()}
            isLoading={registerMutation.isPending}
            disabled={!username || !email || !password}
          >
            Create user
          </Button>
        </CardBody>
      </Card>
    </div>
  );
}
