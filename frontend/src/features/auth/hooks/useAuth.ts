/**
 * src/features/auth/hooks/useAuth.ts
 *
 * Purpose:
 *   The sanctioned access point for auth state. Components never import
 *   AuthContext directly — they call useAuth(), which also fails loudly
 *   if used outside AuthProvider (a real bug, not a silent undefined).
 */
import { useContext } from "react";
import { AuthContext, type AuthContextValue } from "../context/AuthContext";

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth() must be used within an <AuthProvider>");
  }
  return context;
}
