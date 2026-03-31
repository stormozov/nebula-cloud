import { createApi } from "@reduxjs/toolkit/query/react";

import { baseQueryWithAuthErrorHandling } from "@/shared/api";
import type { PaginatedResponse } from "@/shared/types/api";
import { camelToSnake } from "@/shared/utils";

import type {
  IAdminApiResponse,
  IStorageStatsResponse,
  IUser,
  IUserListResponse,
  UserDetailsResponse,
} from "../model/types";

/**
 * API slice for admin-related operations.
 */
export const adminApi = createApi({
  reducerPath: "adminApi",
  baseQuery: baseQueryWithAuthErrorHandling,
  tagTypes: ["User"],
  endpoints: (builder) => ({
    /**
     * Fetches a list of all users.
     */
    getUsers: builder.query<
      PaginatedResponse<IUserListResponse>,
      { page?: number; pageSize?: number } | undefined
    >({
      query: (params) => {
        const queryParams = new URLSearchParams();

        if (params?.page) queryParams.append("page", String(params.page));
        if (params?.pageSize) {
          queryParams.append("page_size", String(params.pageSize));
        }

        const queryString = queryParams.toString();
        return `/admin/users/${queryString ? `?${queryString}` : ""}`;
      },
      providesTags: (result) => {
        if (result?.results) {
          return [
            ...result.results.map(({ id }) => ({ type: "User" as const, id })),
            { type: "User" as const, id: "LIST" },
          ];
        }
        return [{ type: "User" as const, id: "LIST" }];
      },
    }),

    /**
     * Fetches details of a specific user by ID.
     */
    getUser: builder.query<UserDetailsResponse, number>({
      query: (id) => `/admin/users/${id}/`,
      providesTags: (_, __, id) => [{ type: "User", id }],
    }),

    /**
     * Updates details of a specific user by ID.
     */
    updateUser: builder.mutation<
      UserDetailsResponse,
      { id: number; data: Partial<IUser> }
    >({
      query: ({ id, data }) => ({
        url: `/admin/users/${id}/`,
        method: "PATCH",
        body: camelToSnake(data),
      }),
      invalidatesTags: (_, __, { id }) => [{ type: "User", id }],
    }),

    /**
     * Deletes a user by ID.
     */
    deleteUser: builder.mutation<IAdminApiResponse, number>({
      query: (id) => ({
        url: `/admin/users/${id}/`,
        method: "DELETE",
      }),
      invalidatesTags: ["User"],
    }),

    /**
     * Resets a user's password.
     */
    resetPassword: builder.mutation<
      IAdminApiResponse,
      { id: number; newPassword: string }
    >({
      query: ({ id, newPassword }) => ({
        url: `/admin/users/${id}/password/`,
        method: "POST",
        body: camelToSnake({ newPassword }),
      }),
    }),

    /**
     * Toggles a user's admin status.
     */
    toggleAdmin: builder.mutation<
      { isStaff: boolean },
      { id: number; isStaff: boolean }
    >({
      query: ({ id, isStaff }) => ({
        url: `/admin/users/${id}/toggle-admin/`,
        method: "POST",
        body: camelToSnake({ isStaff }),
      }),
      invalidatesTags: (_, __, { id }) => [{ type: "User", id }],
    }),

    /**
     * Fetches storage statistics for a specific user.
     */
    getStorageStats: builder.query<IStorageStatsResponse, number>({
      query: (id) => `/admin/users/${id}/storage-stats/`,
    }),

    /**
     * Exports user data as a JSON file for a specific user.
     */
    exportUserData: builder.mutation<IAdminApiResponse, number>({
      query: (id) => ({
        url: `/admin/users/${id}/export/`,
        method: "GET",
      }),
    }),
  }),
});

export const {
  useGetUsersQuery,
  useGetUserQuery,
  useUpdateUserMutation,
  useDeleteUserMutation,
  useResetPasswordMutation,
  useToggleAdminMutation,
  useGetStorageStatsQuery,
  useExportUserDataMutation,
} = adminApi;
