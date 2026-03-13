import { createBrowserRouter } from "react-router";

import { AuthGuard } from "@/app/providers/AuthGuard";

import { lazyWithSuspense } from "./utils/lazyWithSuspense";

/**
 * Main router for the application with protected routes.
 */
export const routesConfig = createBrowserRouter([
  // Public route: Welcome page (guest only)
  {
    path: "/",
    element: (
      <AuthGuard accessLevel="guest">
        {lazyWithSuspense(() => import("@/pages/PageWelcome/PageWelcome"))}
      </AuthGuard>
    ),
  },

  // Public route: Auth page (guest only)
  {
    path: "/auth",
    element: (
      <AuthGuard accessLevel="guest">
        {lazyWithSuspense(() => import("@/pages/PageAuth/ui/Page/PageAuth"))}
      </AuthGuard>
    ),
  },

  // Protected route: Client Disk (authenticated users)
  {
    path: "/disk",
    element: (
      <AuthGuard accessLevel="user">
        {lazyWithSuspense(
          () => import("@/pages/PageClientDisk/PageClientDisk"),
        )}
      </AuthGuard>
    ),
  },

  // 404 page (always accessible)
  {
    path: "*",
    element: lazyWithSuspense(
      () => import("@/pages/PageNotFound/PageNotFound"),
    ),
  },
]);
