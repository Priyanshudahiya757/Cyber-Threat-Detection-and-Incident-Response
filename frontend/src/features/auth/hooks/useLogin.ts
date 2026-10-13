/**
 * src/features/auth/hooks/useLogin.ts
 *
 * Purpose:
 *   Wraps AuthContext.login() in a React Query mutation so LoginForm
 *   gets loading/error state, retry semantics, and consistent handling
 *   for free, matching how every other mutation in the app is built
 *   (see e.g. future src/features/logs/hooks/useUploadLog.ts).
 */
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./useAuth";
import type { LoginRequest } from "@/types";

interface LoginVariables {
  credentials: LoginRequest;
  remember: boolean;
}

export function useLogin() {
  const { login } = useAuth();
  const navigate = useNavigate();

  return useMutation({
    mutationFn: ({ credentials, remember }: LoginVariables) => login(credentials, remember),
    onSuccess: () => {
      navigate("/dashboard", { replace: true });
    },
  });
}
