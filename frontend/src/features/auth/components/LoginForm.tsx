/**
 * src/features/auth/components/LoginForm.tsx
 *
 * Purpose:
 *   The login form itself — validation (React Hook Form + Zod), the
 *   "Remember me" checkbox, and surfacing backend error responses
 *   (invalid credentials -> 401 from backend/app/api/v1/auth.py::login).
 *   Kept separate from LoginPage so the page component only owns layout.
 */
import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { isAxiosError } from "axios";
import { Eye, EyeOff, Lock, User } from "lucide-react";
import { Button, Input } from "@/components/ui";
import { useLogin } from "../hooks/useLogin";

const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
  remember: z.boolean(),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export function LoginForm() {
  const [showPassword, setShowPassword] = useState(false);
  const loginMutation = useLogin();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: "", password: "", remember: true },
  });

  const onSubmit = (values: LoginFormValues) => {
    loginMutation.mutate({
      credentials: { username: values.username, password: values.password },
      remember: values.remember,
    });
  };

  const errorMessage = getErrorMessage(loginMutation.error);

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
      <Input
        label="Username"
        icon={<User className="h-4 w-4" />}
        placeholder="analyst"
        autoComplete="username"
        autoFocus
        error={errors.username?.message}
        {...register("username")}
      />

      <div className="relative">
        <Input
          label="Password"
          type={showPassword ? "text" : "password"}
          icon={<Lock className="h-4 w-4" />}
          placeholder="••••••••"
          autoComplete="current-password"
          error={errors.password?.message}
          {...register("password")}
        />
        <button
          type="button"
          onClick={() => setShowPassword((v) => !v)}
          className="absolute right-3 top-[34px] text-text-muted hover:text-text-secondary"
          aria-label={showPassword ? "Hide password" : "Show password"}
        >
          {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>

      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 text-sm text-text-secondary">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-border bg-base-800 text-accent-cyan focus-visible:ring-accent-cyan"
            {...register("remember")}
          />
          Remember me
        </label>
      </div>

      {errorMessage && (
        <div
          role="alert"
          className="rounded-md border border-severity-critical/30 bg-severity-critical-dim/30 px-3 py-2 text-sm text-severity-critical"
        >
          {errorMessage}
        </div>
      )}

      <Button type="submit" className="w-full" isLoading={loginMutation.isPending}>
        {loginMutation.isPending ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}

function getErrorMessage(error: unknown): string | null {
  if (!error) return null;
  if (isAxiosError(error)) {
    if (error.response?.status === 401) return "Incorrect username or password.";
    if (error.response?.status === 403) return "This account is disabled.";
    if (!error.response) return "Can't reach the server. Check that the backend is running.";
    return error.response.data?.detail ?? "Sign in failed. Please try again.";
  }
  return "Sign in failed. Please try again.";
}
