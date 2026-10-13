/**
 * src/types/auth.types.ts
 *
 * Purpose:
 *   Mirrors backend/app/models/user_schema.py exactly. Field names and
 *   types here must stay in sync with that file — this is the frontend
 *   half of the API contract referenced throughout the backend's own
 *   docstrings ("Connects to: ...").
 */

export type UserRole = "admin" | "soc_analyst";

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

export interface RefreshRequest {
  refresh_token: string;
}

export interface UserCreateRequest {
  username: string;
  email: string;
  password: string;
  role: UserRole;
}
