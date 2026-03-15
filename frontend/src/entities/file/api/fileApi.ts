import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import axios from "axios";

import {
  removeFile,
  setError,
  setFileList,
  setLoading,
  updateFile,
} from "../model/slice";
import type {
  IFile,
  IFileComment,
  IFileRename,
  IFileUpload,
} from "../model/types";

/**
 * Base configuration for RTK Query API calls.
 *
 * Defines the common settings used across all endpoints in the API slice:
 * - Sets the base URL from environment variables or defaults to `/api`.
 * - Attaches authorization and content-type headers to every request.
 */
const baseQuery = fetchBaseQuery({
  baseUrl: import.meta.env.VITE_API_BASE_URL || "/api",
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

/**
 * Separate axios instance for file upload
 */
const uploadAxios = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
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

/**
 * RTK Query API slice for file-related operations.
 */
export const fileApi = createApi({
  reducerPath: "fileApi",
  baseQuery,
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
    getFiles: build.query<IFile[], void>({
      query: () => "/storage/files/",
      providesTags: ["File"],
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        dispatch(setLoading(true));
        try {
          const { data } = await queryFulfilled;
          dispatch(setFileList(data));
        } catch {
          dispatch(setError("Не удалось загрузить список файлов"));
        } finally {
          dispatch(setLoading(false));
        }
      },
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
      async onQueryStarted(id, { dispatch, queryFulfilled }) {
        try {
          await queryFulfilled;
          dispatch(removeFile(id));
        } catch {
          dispatch(setError("Не удалось удалить файл"));
        }
      },
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
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(updateFile(data));
        } catch {
          dispatch(setError("Не удалось переименовать файл"));
        }
      },
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
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(updateFile(data));
        } catch {
          dispatch(setError("Не удалось обновить комментарий"));
        }
      },
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
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(updateFile(data));
        } catch {
          dispatch(setError("Не удалось создать публичную ссылку"));
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
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          dispatch(updateFile(data));
        } catch {
          dispatch(setError("Не удалось удалить публичную ссылку"));
        }
      },
    }),
  }),
});

/**
 * Uploads a file to the storage.
 */
export const uploadFile = async (
  data: IFileUpload,
  onProgress?: (progress: number) => void,
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

export const {
  useGetFilesQuery,
  useGetFileQuery,
  useDeleteFileMutation,
  useRenameFileMutation,
  useUpdateCommentMutation,
  useGeneratePublicLinkMutation,
  useDeletePublicLinkMutation,
} = fileApi;
