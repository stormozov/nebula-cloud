import { createBrowserRouter } from "react-router";

import { AuthGuard } from "@/app/providers/AuthGuard";
import { RootLayout } from "@/shared/ui";

import { lazyWithSuspense } from "./utils/lazyWithSuspense";

/**
 * Main router for the application with protected routes.
 */
export const routesConfig = createBrowserRouter([
  {
    path: "/",
    element: <RootLayout />,
    children: [
      // Public route: Welcome page (guest only)
      {
        index: true,
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
            {lazyWithSuspense(
              () => import("@/pages/PageAuth/ui/Page/PageAuth"),
            )}
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

      // Public route: Public file metadata preview
      {
        path: "/public/:token/",
        element: lazyWithSuspense(
          () => import("@/pages/PagePublicFile/ui/PagePublicFile"),
        ),
      },

      // 404 page (always accessible)
      {
        path: "*",
        element: lazyWithSuspense(
          () => import("@/pages/PageNotFound/PageNotFound"),
        ),
      },
    ],
  },
]);
