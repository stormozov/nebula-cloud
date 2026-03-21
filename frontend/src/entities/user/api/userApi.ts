import { createApi } from "@reduxjs/toolkit/query/react";

import { baseQueryWithAuthErrorHandling } from "@/shared/api";
import { getRefreshTokenFromPersist } from "@/shared/utils";

import { logout, setAuthData } from "../model/slice";
import type {
  IToken,
  IUser,
  IUserAuthResponse,
  IUserLogin,
  IUserRegister,
} from "../model/types";
import { transformDataToApi } from "../model/utils";

/**
 * RTK Query API slice for user-related operations.
 */
export const userApi = createApi({
  reducerPath: "userApi",
  baseQuery: baseQueryWithAuthErrorHandling,
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
          refresh: getRefreshTokenFromPersist(),
        },
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          await queryFulfilled;
        } finally {
          dispatch(logout());
        }
      },
    }),

    /**
     * RTK Query mutation endpoint for refreshing an authentication token.
     *
     * @returns A configured RTK Query mutation that triggers a token refresh
     * request.
     */
    refresh: build.mutation<IToken, void>({
      query: () => ({
        url: "/auth/refresh/",
        method: "POST",
        body: { refresh: getRefreshTokenFromPersist() },
      }),
    }),
  }),
});

export const {
  useGetMeQuery,
  useLoginMutation,
  useRegisterMutation,
  useLogoutMutation,
  useRefreshMutation,
} = userApi;
