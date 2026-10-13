/**
 * src/services/userService.ts
 * Account administration (backend/app/api/v1/users.py). Everything
 * except listAssignable() is admin-only.
 */
import { apiClient } from "@/api/client";
import { ENDPOINTS } from "@/api/endpoints";
import type { UserCreateRequest, UserPublic, UserUpdateRequest } from "@/types";

export const userService = {
  async list(): Promise<UserPublic[]> {
    const response = await apiClient.get<UserPublic[]>(ENDPOINTS.users.list);
    return response.data;
  },

  /** Usernames of active accounts, for the incident assignee picker. */
  async listAssignable(): Promise<string[]> {
    const response = await apiClient.get<string[]>(ENDPOINTS.users.assignable);
    return response.data;
  },

  async create(body: UserCreateRequest): Promise<UserPublic> {
    const response = await apiClient.post<UserPublic>(ENDPOINTS.users.list, body);
    return response.data;
  },

  async update(username: string, body: UserUpdateRequest): Promise<UserPublic> {
    const response = await apiClient.patch<UserPublic>(ENDPOINTS.users.detail(username), body);
    return response.data;
  },

  async resetPassword(username: string, newPassword: string): Promise<void> {
    await apiClient.post(ENDPOINTS.users.resetPassword(username), { new_password: newPassword });
  },
};
