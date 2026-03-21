import type { BaseQueryFn, FetchArgs } from "@reduxjs/toolkit/query";
import { fetchBaseQuery } from "@reduxjs/toolkit/query";

import { snakeToCamel } from "../utils";
import { API_BASE_URL } from "./apiBaseUrl";
import { getRefreshedToken } from "./tokenRefresh";

// =============================================================================
// BASE QUERY
// =============================================================================

/**
 * Base configuration for RTK Query API calls.
 *
 * Defines the common settings used across all endpoints:
 * - Sets the base URL from environment variables
 * - Attaches authorization and content-type headers
 */
export const baseQuery = fetchBaseQuery({
  baseUrl: API_BASE_URL,
  prepareHeaders: (headers) => {
    const token = localStorage.getItem("persist:auth");

    if (token) {
      try {
        const parsed = JSON.parse(token) as { accessToken?: string };
        const accessToken = parsed.accessToken
          ? JSON.parse(parsed.accessToken)
          : null;
        if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      } catch {
        // Ignore parse errors
      }
    }

    headers.set("Content-Type", "application/json");
    return headers;
  },
});

// =============================================================================
// BASE QUERY WITH TRANSFORM
// =============================================================================

/**
 * Custom baseQuery wrapper that transforms snake_case → camelCase.
 *
 * Uses the base baseQuery for HTTP requests and applies transformation
 * to response.
 */
export const baseQueryWithAuthErrorHandling: BaseQueryFn<
  string | FetchArgs,
  unknown,
  unknown
> = async (args, api, extraOptions) => {
  let result = await baseQuery(args, api, extraOptions);

  if (result.error && "status" in result.error && result.error.status === 401) {
    try {
      const newToken = await getRefreshedToken();

      if (typeof args === "string") args = { url: args };

      let headers: Record<string, string> = {};

      if (args.headers) {
        if (args.headers instanceof Headers) {
          args.headers.forEach((value, key) => {
            headers[key] = value;
          });
        } else if (Array.isArray(args.headers)) {
          headers = Object.fromEntries(args.headers);
        } else {
          for (const [key, value] of Object.entries(args.headers)) {
            if (value !== undefined) headers[key] = String(value);
          }
        }
      }

      headers.Authorization = `Bearer ${newToken}`;
      args.headers = headers;

      result = await baseQuery(args, api, extraOptions);
    } catch {
      const { logout } = await import("@/entities/user");
      api.dispatch(logout());
    }
  }

  if (result.data) {
    result.data = snakeToCamel(result.data);
  }

  return result;
};
