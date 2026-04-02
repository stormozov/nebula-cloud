import { createApi } from "@reduxjs/toolkit/query/react";
import axios from "axios";

import {
  API_BASE_URL,
  baseQueryWithAuthErrorHandling,
  fetchWithAuth,
  getRefreshedToken,
} from "@/shared/api";
import type { PaginatedResponse } from "@/shared/types/api";
import { downloadFile } from "@/shared/utils";

import type {
  IFile,
  IFileComment,
  IFileRename,
  IFileUpload,
} from "../model/types";

// =============================================================================
// UPLOAD AXIOS
// =============================================================================

/**
 * Separate axios instance for file upload
 */
const uploadAxios = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "multipart/form-data",
  },
});

// Add auth interceptor for upload axios
uploadAxios.interceptors.request.use((config) => {
  const token = localStorage.getItem("persist:auth");

  if (token) {
    try {
      const parsed = JSON.parse(token) as { accessToken?: string };
      const accessToken = parsed.accessToken
        ? JSON.parse(parsed.accessToken)
        : null;
      if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
    } catch {
      // Ignore parse errors
    }
  }

  return config;
});

uploadAxios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const newToken = await getRefreshedToken();
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return uploadAxios(originalRequest);
      } catch {
        const { logout } = await import("@/entities/user");
        const { store } = await import("@/app/store/store");
        store.dispatch(logout());
        return Promise.reject(error);
      }
    }
    return Promise.reject(error);
  },
);

// =============================================================================
// RTK QUERY API SLICE
// =============================================================================

/**
 * RTK Query API slice for file-related operations.
 */
export const fileApi = createApi({
  reducerPath: "fileApi",
  baseQuery: baseQueryWithAuthErrorHandling,
  tagTypes: ["File"],
  endpoints: (build) => ({
    /**
     * Fetches the list of all files from the storage.
     *
     * @returns A query that resolves to an array of `IFile` objects.
     *
     * On success, dispatches the fetched file list to the store via
     * `setFileList`. On error, sets an error message indicating failure
     * to load the file list. Sets loading state before and after the request
     * using `setLoading`.
     */
    getFiles: build.query<
      PaginatedResponse<IFile>,
      { userId?: number; page?: number; search?: string }
    >({
      query: (params) => {
        const queryParams = new URLSearchParams();

        if (params?.userId) {
          queryParams.append("user_id", String(params.userId));
        }
        if (params?.page) queryParams.append("page", String(params.page));
        if (params?.search) {
          queryParams.append("search", String(params.search));
        }

        const queryString = queryParams.toString();
        return `/storage/files/${queryString ? `?${queryString}` : ""}`;
      },
      providesTags: (result) =>
        result
          ? [
              ...result.results.map(({ id }) => ({
                type: "File" as const,
                id,
              })),
              { type: "File", id: "LIST" },
            ]
          : [{ type: "File", id: "LIST" }],
    }),

    /**
     * Retrieves a single file by its ID.
     *
     * @param id - The unique identifier of the file to retrieve.
     * @returns A query that resolves to an `IFile` object.
     *
     * Caches the result with a tag specific to the file ID for efficient
     * invalidation.
     */
    getFile: build.query<IFile, number>({
      query: (id) => `/storage/files/${id}/`,
      providesTags: (_, __, id) => [{ type: "File", id }],
    }),

    /**
     * Deletes a file by its ID.
     *
     * @param id - The unique identifier of the file to delete.
     * @returns A mutation that performs a DELETE request to remove the file.
     *
     * On success, removes the file from the local store via `removeFile`.
     * On error, sets an error message indicating failure to delete the file.
     * Invalidates the "File" cache tag to trigger refetching of file lists.
     */
    deleteFile: build.mutation<void, number>({
      query: (id) => ({
        url: `/storage/files/${id}/`,
        method: "DELETE",
      }),
      invalidatesTags: ["File"],
    }),

    /**
     * Renames a file by its ID.
     *
     * @param id - The unique identifier of the file to rename.
     * @param data - An object containing the new name for the file
     *  (`IFileRename`).
     * @returns A mutation that performs a PATCH request to update the file
     *  name.
     *
     * On success, updates the file in the local store via `updateFile`.
     * On error, sets an error message indicating failure to rename the file.
     * Invalidates the "File" cache tag to refresh cached data.
     */
    renameFile: build.mutation<IFile, { id: number; data: IFileRename }>({
      query: ({ id, data }) => ({
        url: `/storage/files/${id}/rename/`,
        method: "PATCH",
        body: data,
      }),
      invalidatesTags: ["File"],
    }),

    /**
     * Updates the comment of a file by its ID.
     *
     * @param id - The unique identifier of the file.
     * @param data - An object containing the new comment (`IFileComment`).
     * @returns A mutation that performs a PATCH request to update the file's
     *  comment.
     *
     * On success, updates the file in the local store via `updateFile`.
     * On error, sets an error message indicating failure to update the comment.
     * Invalidates the "File" cache tag to ensure updated data is reflected.
     */
    updateComment: build.mutation<IFile, { id: number; data: IFileComment }>({
      query: ({ id, data }) => ({
        url: `/storage/files/${id}/comment/`,
        method: "PATCH",
        body: data,
      }),
      invalidatesTags: ["File"],
    }),

    /**
     * Generates a public link for a file by its ID.
     *
     * @param id - The unique identifier of the file.
     * @returns A mutation that performs a POST request to generate a public
     *  link.
     *
     * On success, updates the file in the store with the new public link via
     * `updateFile`. On error, sets an error message indicating failure
     * to generate the link. Invalidates the "File" cache tag to refresh
     * the file data.
     */
    generatePublicLink: build.mutation<IFile, number>({
      query: (id) => ({
        url: `/storage/files/${id}/public-link/generate/`,
        method: "POST",
      }),
      invalidatesTags: ["File"],
    }),

    /**
     * Retrieves public file metadata by token.
     * No authentication required.
     *
     * @param token - Public access token
     * @returns File metadata (original_name, size, download_url, etc.)
     */
    getPublicFile: build.query<IFile, string>({
      query: (token) => `/storage/public/${token}/`,
      keepUnusedDataFor: 60, // 1 minute
    }),

    /**
     * Downloads public file by token.
     * No authentication required.
     *
     * @param token - Public access token
     * @returns File blob with original filename
     */
    downloadPublicFile: build.mutation<
      Blob,
      { token: string; filename: string }
    >({
      queryFn: async ({ token }, _queryApi, _extraOptions) => {
        try {
          const response = await fetch(
            `${API_BASE_URL}/storage/public/${token}/download/`,
          );

          if (!response.ok) {
            throw new Error(`Download failed: ${response.status}`);
          }

          const blob: Blob = await response.blob();
          return { data: blob };
        } catch (error) {
          return { error: error as Error };
        }
      },
    }),

    /**
     * Deletes the public link of a file by its ID.
     *
     * @param id - The unique identifier of the file.
     * @returns A mutation that performs a DELETE request to remove the public
     *  link.
     *
     * On success, updates the file in the store to reflect the removed public
     * link via `updateFile`. On error, sets an error message indicating failure
     * to delete the public link. Invalidates the "File" cache tag to ensure
     * consistency across caches.
     */
    deletePublicLink: build.mutation<IFile, number>({
      query: (id) => ({
        url: `/storage/files/${id}/public-link/`,
        method: "DELETE",
      }),
      invalidatesTags: ["File"],
    }),
  }),
});

/**
 * Uploads a file to the storage.
 */
export const uploadFile = async (
  data: IFileUpload,
  onProgress?: (progress: number) => void,
  _signal?: AbortSignal,
): Promise<IFile> => {
  const formData = new FormData();
  formData.append("file", data.file);

  if (data.comment !== undefined) {
    formData.append("comment", data.comment);
  }

  const response = await uploadAxios.post<IFile>("/storage/files/", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
    onUploadProgress: (progressEvent) => {
      if (progressEvent.total && onProgress) {
        const percent = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total,
        );
        onProgress(percent);
      }
    },
  });

  return response.data;
};

/**
 * Downloads file from API with authentication.
 *
 * Uses fetch directly for blob handling (not RTK Query).
 */
export const downloadFileFromApi = async (
  fileId: number,
  filename: string,
): Promise<void> => {
  try {
    const blob = await getImageBlobFromApi(fileId);
    await downloadFile(blob, filename);
  } catch (error) {
    if (error instanceof Response && error.status === 401) return;
    console.error("Download failed:", error);
  }
};

/**
 * Gets file blob from API with authentication (no download).
 * Reusable for previews/modals.
 */
export const getImageBlobFromApi = async (fileId: number): Promise<Blob> => {
  try {
    const response = await fetchWithAuth(
      `${API_BASE_URL}/storage/files/${fileId}/download/`,
      { method: "GET" },
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.blob();
  } catch (error) {
    if (error instanceof Response && error.status === 401) throw error;
    throw error;
  }
};

export const {
  useGetFilesQuery,
  useGetFileQuery,
  useDeleteFileMutation,
  useRenameFileMutation,
  useUpdateCommentMutation,
  useGeneratePublicLinkMutation,
  useDeletePublicLinkMutation,
  useGetPublicFileQuery,
  useDownloadPublicFileMutation,
} = fileApi;
