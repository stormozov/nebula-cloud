import { useAppSelector } from "@/app/store/hooks";
import { selectUploadStats } from "@/entities/file-upload";

import type { IUseFileUploadQueueReturn } from "../types";

/**
 * Custom hook for managing file upload queue state.
 *
 * Watches Redux store for active upload and provides queue statistics.
 *
 * Note: This hook does NOT trigger uploads directly. File uploads are
 * initiated from UI components (FileUploadPanel) when they detect
 * activeUploadId changes. This hook only manages queue state and
 * provides statistics for UI rendering.
 *
 * @returns {IUseFileUploadQueueReturn} Queue state information
 */
export const useFileUploadQueue = (): IUseFileUploadQueueReturn => {
  const stats = useAppSelector(selectUploadStats);
  return {
    isUploading: stats.uploading > 0,
    queueLength: stats.total,
    completedCount: stats.success,
    failedCount: stats.error,
    pendingCount: stats.pending,
  };
};
