import { createSlice, type PayloadAction } from "@reduxjs/toolkit";

import type { IFile, IFileState } from "./types";

/**
 * Initial state for the file slice.
 */
const initialState: IFileState = {
  fileList: [],
  selectedFile: null,
  isLoading: false,
  isUploading: false,
  uploadProgress: 0,
  error: null,
};

/**
 * A Redux slice for managing the state of files in the application.
 *
 * This slice handles the file list, selected file, loading and uploading
 * states, upload progress, and error states. It provides reducers to update
 * the state in response to user actions and API events.
 *
 * All reducers automatically clear the error state on successful updates,
 * unless explicitly setting an error.
 */
export const fileSlice = createSlice({
  name: "file",
  initialState,
  reducers: {
    /**
     * Sets the list of files in the state.
     *
     * Also clears any existing error upon successful setting of the file list.
     *
     * @param state - The current Redux state.
     * @param action - An action containing an array of `IFile` objects
     *  as payload.
     */
    setFileList: (state, action: PayloadAction<IFile[]>) => {
      state.fileList = action.payload;
      state.error = null;
    },

    /**
     * Sets the currently selected file.
     *
     * Used to track which file is currently active in the UI
     * (e.g., for preview or editing).
     *
     * @param state - The current Redux state.
     * @param action - An action containing either an `IFile` object or `null`
     *  as payload.
     */
    setSelectedFile: (state, action: PayloadAction<IFile | null>) => {
      state.selectedFile = action.payload;
    },

    /**
     * Adds a new file to the beginning of the file list.
     *
     * Also clears any existing error after adding the file.
     *
     * @param state - The current Redux state.
     * @param action - An action containing the `IFile` object to add.
     */
    addFile: (state, action: PayloadAction<IFile>) => {
      state.fileList.unshift(action.payload);
      state.error = null;
    },

    /**
     * Updates an existing file in the file list and optionally the selected
     * file.
     *
     * Locates the file by ID in the `fileList` and replaces it.
     * If the updated file is also the `selectedFile`, it updates that as well.
     * Clears any existing error after the update.
     *
     * @param state - The current Redux state.
     * @param action - An action containing the updated `IFile` object.
     */
    updateFile: (state, action: PayloadAction<IFile>) => {
      const index = state.fileList.findIndex((f) => f.id === action.payload.id);

      if (index !== -1) state.fileList[index] = action.payload;
      if (state.selectedFile?.id === action.payload.id) {
        state.selectedFile = action.payload;
      }

      state.error = null;
    },

    /**
     * Removes a file from the file list by its ID.
     *
     * Also sets `selectedFile` to `null` if the removed file was selected.
     * Clears any existing error after removal.
     *
     * @param state - The current Redux state.
     * @param action - An action containing the `id` of the file to remove.
     */
    removeFile: (state, action: PayloadAction<number>) => {
      state.fileList = state.fileList.filter((f) => f.id !== action.payload);
      if (state.selectedFile?.id === action.payload) state.selectedFile = null;
      state.error = null;
    },

    /**
     * Sets the loading state.
     *
     * Used to show loading indicators during file fetches or deletions.
     *
     * @param state - The current Redux state.
     * @param action - An action containing a boolean value indicating whether
     *  loading is active.
     */
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.isLoading = action.payload;
    },

    /**
     * Sets the uploading state.
     *
     * Used to control UI elements related to file uploads.
     *
     * @param state - The current Redux state.
     * @param action - An action containing a boolean value indicating whether
     *  uploading is in progress.
     */
    setUploading: (state, action: PayloadAction<boolean>) => {
      state.isUploading = action.payload;
    },

    /**
     * Sets the upload progress percentage.
     *
     * This value is typically updated during file upload via Axios interceptors
     * or upload events.
     *
     * @param state - The current Redux state.
     * @param action - An action containing a number between 0 and 100
     *  representing upload progress.
     */
    setUploadProgress: (state, action: PayloadAction<number>) => {
      state.uploadProgress = action.payload;
    },

    /**
     * Sets an error message and resets loading/uploading states.
     *
     * Also sets `isLoading` and `isUploading` to `false` to ensure stalled
     * processes are cleared.
     *
     * @param state - The current Redux state.
     * @param action - An action containing an error message (`string`)
     *  or `null`.
     */
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload;
      state.isLoading = false;
      state.isUploading = false;
    },

    /**
     * Clears the current error message without changing other state values.
     *
     * Useful for dismissing errors after user acknowledgment.
     *
     * @param state - The current Redux state.
     */
    clearError: (state) => {
      state.error = null;
    },

    /**
     * Resets the entire file state to its initial values.
     *
     * Clears file list, selection, loading, uploading, progress, and error
     * states. Used when logging out or resetting the file module entirely.
     *
     * @param state - The current Redux state.
     */
    resetState: (state) => {
      state.fileList = [];
      state.selectedFile = null;
      state.isLoading = false;
      state.isUploading = false;
      state.uploadProgress = 0;
      state.error = null;
    },
  },
});

export const {
  setFileList,
  setSelectedFile,
  addFile,
  updateFile,
  removeFile,
  setLoading,
  setUploading,
  setUploadProgress,
  setError,
  clearError,
  resetState,
} = fileSlice.actions;

export default fileSlice.reducer;
