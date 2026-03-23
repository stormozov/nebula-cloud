import type { IUploadFile } from "./types";

/**
 * Generates unique upload ID for tracking individual uploads.
 */
export const generateUploadId = (): string => {
  return `upload_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
};

/**
 * Finds next pending file in queue.
 */
export const findNextPendingFile = (
  queue: IUploadFile[],
): IUploadFile | undefined => {
  return queue.find((file) => file.status === "pending");
};

/**
 * Checks if all uploads are completed (success or error).
 */
export const areAllUploadsCompleted = (queue: IUploadFile[]): boolean => {
  return (
    queue.length > 0 &&
    queue.every((file) => file.status === "success" || file.status === "error")
  );
};
