import {
  type BaseQueryFn,
  type FetchArgs,
  fetchBaseQuery,
} from "@reduxjs/toolkit/query";

import { snakeToCamel } from "../utils";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";

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
export const baseQueryWithTransform: BaseQueryFn<
  string | FetchArgs,
  unknown,
  unknown
> = async (args, api, extraOptions) => {
  const result = await baseQuery(args, api, extraOptions);

  // Transform response data if present
  if (result.data) result.data = snakeToCamel(result.data);

  return result;
};
