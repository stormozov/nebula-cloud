import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import {
  cancelUpload,
  clearCompleted,
  type IUploadFile,
  removeFile,
  retryUpload,
  selectCanClosePanel,
  selectIsPanelVisible,
  selectIsQueueCompleted,
  selectUploadQueue,
  selectUploadStats,
  setPanelVisible,
} from "@/entities/file-upload";
import { useAnimatedClose } from "@/shared/hooks";

/**
 * Interface defining the return value structure of the `useFileUploadPanel`
 * hook.
 */
export interface IFileUploadPanelReturns {
  /** The current queue of files to be uploaded. */
  queue: IUploadFile[];
  /** Flag indicating whether the file upload panel is currently visible. */
  isPanelVisible: boolean;
  /** Flag indicating whether all uploads in the queue have been completed */
  isQueueCompleted: boolean;
  /** Aggregated statistics about the current state of the upload queue. */
  stats: {
    /** Number of successfully completed uploads. */
    success: number;
    /** Number of uploads that failed. */
    error: number;
    /** Number of uploads currently in progress. */
    uploading: number;
  };
  /** Flag indicating whether the panel is currently closing */
  isClosing: boolean;
  /** Flag indicating whether it is safe to close the panel. */
  canClosePanel: boolean;
  /** Function to initiate the panel closing sequence with animation. */
  handleCloseWithAnimation: () => void;
  /**
   * Function to cancel a specific upload operation.
   *
   * @param uploadId - The unique identifier of the upload to cancel.
   */
  handleCancel: (uploadId: string) => void;
  /**
   * Function to retry a failed upload operation.
   *
   * @param uploadId - The unique identifier of the upload to retry.
   */
  handleRetry: (uploadId: string) => void;
  /**
   * Function to remove a file from the upload queue.
   *
   * @param uploadId - The unique identifier of the upload to remove.
   */
  handleRemove: (uploadId: string) => void;
}

/**
 * Custom hook for managing the file upload panel state and interactions.
 */
export const useFileUploadPanel = (): IFileUploadPanelReturns => {
  const dispatch = useAppDispatch();
  const queue = useAppSelector(selectUploadQueue);
  const isPanelVisible = useAppSelector(selectIsPanelVisible);
  const isQueueCompleted = useAppSelector(selectIsQueueCompleted);
  const canClosePanel = useAppSelector(selectCanClosePanel);
  const stats = useAppSelector(selectUploadStats);

  const { isClosing, handleCloseWithAnimation } = useAnimatedClose({
    onClose: () => {
      dispatch(setPanelVisible(false));
      dispatch(clearCompleted());
    },
    isBlocked: !canClosePanel,
    animationDuration: 300,
  });

  const handleCancel = (uploadId: string): void => {
    dispatch(cancelUpload({ uploadId }));
  };

  const handleRetry = (uploadId: string): void => {
    dispatch(retryUpload({ uploadId }));
    console.warn("Retry upload:", uploadId);
  };

  const handleRemove = (uploadId: string): void => {
    dispatch(removeFile({ uploadId }));
  };

  return {
    queue,
    isPanelVisible,
    isQueueCompleted,
    stats,
    isClosing,
    canClosePanel,
    handleCloseWithAnimation,
    handleCancel,
    handleRetry,
    handleRemove,
  };
};
