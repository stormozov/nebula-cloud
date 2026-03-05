import { createBrowserRouter } from "react-router";

import { lazyWithSuspense } from "./utils";

const basename: string = import.meta.env.VITE_BASENAME;

const router = createBrowserRouter(
	[
		{
			path: "/",
			element: lazyWithSuspense(
				() => import("@/layouts/PageLayout/PageLayout"),
			),
			children: [
				{
					index: true,
					element: lazyWithSuspense(
						() => import("@/pages/PageClientDisk/PageClientDisk"),
					),
				},
				{
					path: "*",
					element: lazyWithSuspense(
						() => import("@/pages/PageNotFound/PageNotFound"),
					),
				},
			],
		},
	],
	{ basename },
);

export default router;
