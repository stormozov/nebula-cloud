import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

import { logout, setAuthData } from "../model/slice";
import type {
  IUser,
  IUserAuthResponse,
  IUserLogin,
  IUserRegister,
} from "../model/types";
import { transformDataToApi } from "../model/utils";

/**
 * Base configuration for RTK Query API calls.
 *
 * Defines the common settings used across all endpoints in the API slice:
 * - Sets the base URL from environment variables or defaults to `/api`.
 * - Attaches authorization and content-type headers to every request.
 */
const baseQuery = fetchBaseQuery({
  /**
   * The root URL for all API requests.
   *
   * Retrieved from the VITE_API_BASE_URL environment variable, falling back
   * to '/api' if not defined.
   */
  baseUrl: import.meta.env.VITE_API_BASE_URL || "/api",

  /**
   * Prepares headers to be sent with each request.
   *
   * Includes an Authorization header with a Bearer token if available
   * in localStorage, and sets the Content-Type to application/json.
   *
   * @param headers - The Headers instance to modify.
   * @returns The modified Headers instance with authentication
   *  and content-type set.
   */
  prepareHeaders: (headers: Headers): Headers => {
    const token = localStorage.getItem("accessToken");
    if (token) headers.set("Authorization", `Bearer ${token}`);
    headers.set("Content-Type", "application/json");
    return headers;
  },
});

/**
 * RTK Query API slice for user-related operations.
 *
 * Provides methods for authentication and user data management, including
 * login, registration, fetching current user details, and logout. Automatically
 * handles authentication token storage and attaches tokens to subsequent
 * requests via {@link baseQuery}.
 */
export const userApi = createApi({
  reducerPath: "userApi",
  baseQuery,
  tagTypes: ["User"],
  endpoints: (build) => ({
    /**
     * Fetches the current authenticated user's data.
     *
     * @returns A query that resolves to an `IUser` object.
     * Caches the result with the "User" tag for automatic invalidation.
     */
    getMe: build.query<IUser, void>({
      query: () => "/users/me/",
      providesTags: ["User"],
    }),

    /**
     * Authenticates a user with provided credentials.
     *
     * On successful login:
     * - Stores authentication tokens in localStorage.
     * - Updates the global auth state via Redux dispatch.
     *
     * @param credentials - An object containing username/email and password.
     * @returns A mutation that sends a POST request to the login endpoint.
     */
    login: build.mutation<IUserAuthResponse, IUserLogin>({
      query: (credentials) => ({
        url: "/auth/login/",
        method: "POST",
        body: credentials,
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(setAuthData(data));
          localStorage.setItem("accessToken", data.access);
          localStorage.setItem("refreshToken", data.refresh);
        } catch {
          // Error handling in component
        }
      },
    }),

    /**
     * Registers a new user.
     *
     * Transforms the registration form data before sending it to the API.
     * On successful registration:
     * - Stores authentication tokens in localStorage.
     * - Updates the global auth state via Redux dispatch.
     *
     * @param data - The user registration data (e.g., username, email,
     *  password).
     * @returns A mutation that sends a POST request to the register endpoint.
     */
    register: build.mutation<IUserAuthResponse, IUserRegister>({
      query: (data) => ({
        url: "/auth/register/",
        method: "POST",
        body: transformDataToApi(data),
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(setAuthData(data));
          localStorage.setItem("accessToken", data.access);
          localStorage.setItem("refreshToken", data.refresh);
        } catch {
          // Error handling in component
        }
      },
    }),

    /**
     * Logs out the current user.
     *
     * Sends a POST request to the logout endpoint and then:
     * - Clears authentication data from Redux state.
     * - Removes tokens from localStorage.
     *
     * @returns A mutation that performs the logout operation.
     */
    logout: build.mutation<void, void>({
      query: () => ({
        url: "/auth/logout/",
        method: "POST",
        body: {
          refresh: localStorage.getItem("refreshToken") || undefined,
        },
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          await queryFulfilled;
        } finally {
          dispatch(logout());
          localStorage.removeItem("accessToken");
          localStorage.removeItem("refreshToken");
        }
      },
    }),
  }),
});

export const {
  useGetMeQuery,
  useLoginMutation,
  useRegisterMutation,
  useLogoutMutation,
} = userApi;
