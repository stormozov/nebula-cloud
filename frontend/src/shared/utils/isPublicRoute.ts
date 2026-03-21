import { matchPath } from "react-router";

import publicRoutesConfig from "@/shared/configs/public-routes.json";

import type { PublicRoutesConfig } from "../types/configs";

/**
 * A constant representing the list of public routes.
 *
 * These are the routes accessible without authentication.
 */
const PUBLIC_ROUTES: PublicRoutesConfig = publicRoutesConfig;

/**
 * Checks if a given path matches any of the public routes.
 *
 * @param path - The path to check against the public route patterns.
 * @param routes_list - An array of public route configurations.
 *
 * @returns `true` if the path matches any public route; otherwise, `false`.
 *
 * @example
 * ```ts
 * isPublicRoute(undefined, '/login'); // returns true if '/login' is a public route
 * ```
 */
export const isPublicRoute = (
  path: string,
  routes_list: PublicRoutesConfig = PUBLIC_ROUTES,
): boolean => {
  return routes_list.some((route) => matchPath(route.path, path));
};
