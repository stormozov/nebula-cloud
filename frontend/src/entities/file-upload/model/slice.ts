import { createSlice, type PayloadAction } from "@reduxjs/toolkit";

import type {
  IAddFilesPayload,
  IRemoveFilePayload,
  IUpdateProgressPayload,
  IUpdateStatusPayload,
  IUploadFile,
  IUploadState,
} from "./types";
import {
  areAllUploadsCompleted,
  findNextPendingFile,
  generateUploadId,
} from "./utils";

//==============================================================================
// SLICE
//==============================================================================

const initialState: IUploadState = {
  queue: [],
  isPanelVisible: false,
  isDropzoneVisible: false,
  activeUploadId: null,
  totalUploaded: 0,
  totalFailed: 0,
  isQueueCompleted: false,
};

export const fileUploadSlice = createSlice({
  name: "fileUpload",
  initialState,
  reducers: {
    /**
     * Add files to upload queue.
     *
     * Creates upload items with 'pending' status.
     * Shows panel automatically.
     * Maximum 5 files per batch (enforced by validator before dispatch).
     */
    addFiles: (state, action: PayloadAction<IAddFilesPayload>) => {
      const { files, comment } = action.payload;

      // Create upload items for each file
      const newUploads: IUploadFile[] = files.map((file) => ({
        id: generateUploadId(),
        file: {
          name: file.name,
          size: file.size,
          type: file.type,
          lastModified: file.lastModified,
          comment: comment || "",
        },
        progress: 0,
        status: "pending",
        needsReupload: false,
        startedAt: undefined,
        completedAt: undefined,
      }));

      // Add to queue
      state.queue.push(...newUploads);

      // Show panel when files are added
      state.isPanelVisible = true;

      // Reset completion flag when new files added
      state.isQueueCompleted = false;

      // Start first file if nothing is uploading
      if (!state.activeUploadId) {
        const nextFile = findNextPendingFile(state.queue);
        if (nextFile) {
          state.activeUploadId = nextFile.id;
          nextFile.status = "uploading";
          nextFile.startedAt = Date.now();
        }
      }
    },

    /**
     * Update upload progress for specific file.
     */
    updateProgress: (state, action: PayloadAction<IUpdateProgressPayload>) => {
      const { uploadId, progress } = action.payload;
      const uploadItem = state.queue.find((item) => item.id === uploadId);

      if (uploadItem && uploadItem.status === "uploading") {
        uploadItem.progress = Math.min(100, Math.max(0, progress));
      }
    },

    /**
     * Update upload status (success/error).
     *
     * Automatically starts next file in queue.
     * Marks queue as completed when all files finished.
     */
    updateStatus: (state, action: PayloadAction<IUpdateStatusPayload>) => {
      const { uploadId, status, error, uploadedFileId } = action.payload;
      const uploadItem = state.queue.find((item) => item.id === uploadId);

      if (!uploadItem) return;

      // Update status
      uploadItem.status = status;
      uploadItem.completedAt = Date.now();

      if (status === "success") {
        uploadItem.progress = 100;
        uploadItem.uploadedFileId = uploadedFileId;
        uploadItem.needsReupload = false;
        state.totalUploaded += 1;
      } else if (status === "error") {
        uploadItem.error = error;
        uploadItem.progress = uploadItem.progress > 0 ? uploadItem.progress : 0;
        uploadItem.needsReupload = false;
        state.totalFailed += 1;
      }

      // Clear active upload
      if (state.activeUploadId === uploadId) {
        state.activeUploadId = null;
      }

      // Start next file in queue (error doesn't stop the queue)
      const nextFile = findNextPendingFile(state.queue);
      if (nextFile) {
        state.activeUploadId = nextFile.id;
        nextFile.status = "uploading";
        nextFile.startedAt = Date.now();
      } else {
        // No more pending files - check if queue is completed
        if (areAllUploadsCompleted(state.queue)) {
          state.isQueueCompleted = true;
          state.activeUploadId = null;
        }
      }
    },

    /**
     * Remove file from upload queue.
     *
     * Can only remove pending or completed (success/error) files.
     * Cannot remove currently uploading file.
     */
    removeFile: (state, action: PayloadAction<IRemoveFilePayload>) => {
      const { uploadId } = action.payload;
      const uploadIndex = state.queue.findIndex((item) => item.id === uploadId);

      if (uploadIndex === -1) return;

      const uploadItem = state.queue[uploadIndex];

      // Cannot remove currently uploading file
      if (uploadItem.status === "uploading") {
        return;
      }

      // Remove from queue
      state.queue.splice(uploadIndex, 1);

      // Update counters if removing completed file
      if (uploadItem.status === "success") {
        state.totalUploaded = Math.max(0, state.totalUploaded - 1);
      } else if (uploadItem.status === "error") {
        state.totalFailed = Math.max(0, state.totalFailed - 1);
      }

      // Reset completion flag if queue not empty
      if (state.queue.length > 0) {
        state.isQueueCompleted = false;
      }

      // Hide panel if queue is empty
      if (state.queue.length === 0) {
        state.isPanelVisible = false;
        state.activeUploadId = null;
        state.isQueueCompleted = false;
      }
    },

    /**
     * Show/hide upload panel manually.
     *
     * Can only hide if queue is completed or empty.
     */
    setPanelVisible: (state, action: PayloadAction<boolean>) => {
      // Can only hide if completed or empty
      if (
        !action.payload &&
        state.queue.length > 0 &&
        !state.isQueueCompleted
      ) {
        return; // Prevent hiding during active uploads
      }
      state.isPanelVisible = action.payload;
    },

    /**
     * Show/hide global dropzone overlay.
     */
    setDropzoneVisible: (state, action: PayloadAction<boolean>) => {
      state.isDropzoneVisible = action.payload;
    },

    /**
     * Cancel active upload.
     *
     * Sets status to error and starts next file.
     */
    cancelUpload: (state, action: PayloadAction<{ uploadId: string }>) => {
      const { uploadId } = action.payload;
      const uploadItem = state.queue.find((item) => item.id === uploadId);

      if (!uploadItem || uploadItem.status !== "uploading") return;

      uploadItem.status = "error";
      uploadItem.error = "Загрузка отменена";
      uploadItem.completedAt = Date.now();
      uploadItem.needsReupload = false;
      state.totalFailed += 1;
      state.activeUploadId = null;

      // Start next file
      const nextFile = findNextPendingFile(state.queue);
      if (nextFile) {
        state.activeUploadId = nextFile.id;
        nextFile.status = "uploading";
        nextFile.startedAt = Date.now();
      } else if (areAllUploadsCompleted(state.queue)) {
        state.isQueueCompleted = true;
      }
    },

    /**
     * Clear completed uploads from queue.
     *
     * Removes all success and error items.
     * Only allowed when isQueueCompleted = true.
     */
    clearCompleted: (state) => {
      if (!state.isQueueCompleted && state.queue.length > 0) return;

      state.queue = [];
      state.isPanelVisible = false;
      state.isQueueCompleted = false;
      state.activeUploadId = null;
    },

    /**
     * Force clear queue (e.g., on logout).
     *
     * Ignores completion check.
     */
    forceClearQueue: (state) => {
      state.queue = [];
      state.isPanelVisible = false;
      state.isQueueCompleted = false;
      state.activeUploadId = null;
    },

    /**
     * Mark files for re-upload after rehydration.
     *
     * Called automatically by persist transform.
     */
    markForReupload: (state) => {
      state.queue.forEach((item) => {
        if (item.status === "uploading" || item.status === "pending") {
          item.status = "pending";
          item.progress = 0;
          item.needsReupload = true;
        }
      });
      state.activeUploadId = null;
      state.isQueueCompleted = false;

      // Start first pending file
      const nextFile = findNextPendingFile(state.queue);
      if (nextFile) {
        state.activeUploadId = nextFile.id;
        nextFile.status = "uploading";
        nextFile.startedAt = Date.now();
      }
    },

    /**
     * Reset upload state (e.g., on logout).
     */
    resetState: (state) => {
      state.queue = [];
      state.isPanelVisible = false;
      state.isDropzoneVisible = false;
      state.activeUploadId = null;
      state.totalUploaded = 0;
      state.totalFailed = 0;
      state.isQueueCompleted = false;
    },
  },
});

//==============================================================================
// EXPORTS
//==============================================================================

export const {
  addFiles,
  updateProgress,
  updateStatus,
  removeFile,
  setPanelVisible,
  setDropzoneVisible,
  cancelUpload,
  clearCompleted,
  forceClearQueue,
  markForReupload,
  resetState,
} = fileUploadSlice.actions;

export default fileUploadSlice.reducer;
