import { createBrowserRouter } from "react-router";

import { lazyWithSuspense } from "./utils";

const basename: string = import.meta.env.VITE_BASENAME;

/**
 * Main router for the application.
 */
const routesConfig = createBrowserRouter(
  [
    {
      path: "/",
      element: lazyWithSuspense(
        () => import("@/pages/PageWelcome/PageWelcome"),
      ),
    },

    {
      path: "/",
      element: lazyWithSuspense(
        () => import("@/shared/ui/layouts/AppLayout/AppLayout"),
      ),
      children: [
        {
          path: "disk",
          element: lazyWithSuspense(
            () => import("@/pages/PageClientDisk/PageClientDisk"),
          ),
        },
      ],
    },

    {
      path: "*",
      element: lazyWithSuspense(
        () => import("@/pages/PageNotFound/PageNotFound"),
      ),
    },
  ],
  { basename },
);

export default routesConfig;
