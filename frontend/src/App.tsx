/**
 * src/App.tsx
 *
 * Purpose:
 *   Composes every app-wide provider in the order that matters:
 *   QueryClientProvider (so auth calls can use React Query) wraps
 *   BrowserRouter (so AuthProvider can use useNavigate-adjacent hooks
 *   if ever needed) wraps AuthProvider (so AppRouter's guards can call
 *   useAuth()) wraps AppRouter.
 */
import { BrowserRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { queryClient } from "@/lib/queryClient";
import { AuthProvider } from "@/features/auth/context/AuthContext";
import { AppRouter } from "@/routes/AppRouter";
import { env } from "@/config/env";

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <AppRouter />
        </AuthProvider>
      </BrowserRouter>
      {env.isDev && <ReactQueryDevtools initialIsOpen={false} />}
    </QueryClientProvider>
  );
}
