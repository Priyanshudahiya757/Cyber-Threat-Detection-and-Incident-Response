/**
 * src/types/auth.types.ts
 * Mirrors backend/app/models/user_schema.py.
 */
export type UserRole = "admin" | "soc_analyst";

export const ROLE_LABELS: Record<UserRole, string> = {
  admin: "Admin",
  soc_analyst: "SOC Analyst",
};

export interface UserPublic {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string; // ISO 8601
  last_login: string | null;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: UserPublic;
}

export interface UserCreateRequest {
  username: string;
  email: string;
  password: string;
  role: UserRole;
}

export interface UserUpdateRequest {
  role?: UserRole;
  is_active?: boolean;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}
