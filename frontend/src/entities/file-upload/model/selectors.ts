import type { RootState } from "@/app/store/store";

/**
 * Get full upload state.
 */
export const selectUploadState = (state: RootState) => state.fileUpload;

/**
 * Get upload queue.
 */
export const selectUploadQueue = (state: RootState) => state.fileUpload.queue;

/**
 * Get currently uploading file.
 */
export const selectActiveUpload = (state: RootState) => {
  const { queue, activeUploadId } = state.fileUpload;
  return queue.find((item) => item.id === activeUploadId) || null;
};

/**
 * Get pending files (waiting in queue).
 */
export const selectPendingUploads = (state: RootState) =>
  state.fileUpload.queue.filter((item) => item.status === "pending");

/**
 * Get uploading files (currently in progress).
 */
export const selectUploadingUploads = (state: RootState) =>
  state.fileUpload.queue.filter((item) => item.status === "uploading");

/**
 * Get completed uploads (success).
 */
export const selectCompletedUploads = (state: RootState) =>
  state.fileUpload.queue.filter((item) => item.status === "success");

/**
 * Get failed uploads (error).
 */
export const selectFailedUploads = (state: RootState) =>
  state.fileUpload.queue.filter((item) => item.status === "error");

/**
 * Check if any file is currently uploading.
 */
export const selectIsUploading = (state: RootState) =>
  state.fileUpload.activeUploadId !== null;

/**
 * Check if there are pending files in queue.
 */
export const selectHasPendingUploads = (state: RootState) =>
  state.fileUpload.queue.some((item) => item.status === "pending");

/**
 * Get upload panel visibility.
 */
export const selectIsPanelVisible = (state: RootState) =>
  state.fileUpload.isPanelVisible;

/**
 * Get global dropzone visibility.
 */
export const selectIsDropzoneVisible = (state: RootState) =>
  state.fileUpload.isDropzoneVisible;

/**
 * Check if queue is completed (all files finished).
 */
export const selectIsQueueCompleted = (state: RootState) =>
  state.fileUpload.isQueueCompleted;

/**
 * Get total uploaded count (session).
 */
export const selectTotalUploaded = (state: RootState) =>
  state.fileUpload.totalUploaded;

/**
 * Get total failed count (session).
 */
export const selectTotalFailed = (state: RootState) =>
  state.fileUpload.totalFailed;

/**
 * Get upload statistics.
 */
export const selectUploadStats = (state: RootState) => ({
  total: state.fileUpload.queue.length,
  pending: state.fileUpload.queue.filter((i) => i.status === "pending").length,
  uploading: state.fileUpload.queue.filter((i) => i.status === "uploading")
    .length,
  success: state.fileUpload.queue.filter((i) => i.status === "success").length,
  error: state.fileUpload.queue.filter((i) => i.status === "error").length,
  totalUploaded: state.fileUpload.totalUploaded,
  totalFailed: state.fileUpload.totalFailed,
  isCompleted: state.fileUpload.isQueueCompleted,
});

/**
 * Get specific upload by ID.
 */
export const selectUploadById = (uploadId: string) => (state: RootState) =>
  state.fileUpload.queue.find((item) => item.id === uploadId) || null;

/**
 * Check if upload panel can be closed.
 */
export const selectCanClosePanel = (state: RootState) =>
  state.fileUpload.isQueueCompleted || state.fileUpload.queue.length === 0;
