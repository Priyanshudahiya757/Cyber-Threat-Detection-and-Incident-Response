import { createContext } from "react";
import type { ChangePasswordRequest, LoginRequest, UserPublic } from "@/types";

export interface AuthContextValue {
  user: UserPublic | null;
  isAuthenticated: boolean;
  isInitializing: boolean;
  login: (credentials: LoginRequest, remember: boolean) => Promise<void>;
  logout: () => void;
  changePassword: (body: ChangePasswordRequest) => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);
