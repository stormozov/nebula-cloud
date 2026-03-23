import { useCallback, useRef, useState } from "react";

import { useAppDispatch } from "@/app/store/hooks";
import { type IFile, uploadFile as uploadFileToApi } from "@/entities/file";
import {
  type UploadStatus,
  updateProgress,
  updateStatus,
} from "@/entities/file-upload";

import type { IUseFileUploadReturn } from "../types";

/**
 * Custom hook for uploading a single file with progress tracking.
 *
 * @returns {IUseFileUploadReturn} Upload state and handlers
 *
 * @example
 * const { uploadFile, progress, isUploading, error, cancelUpload } = useFileUpload();
 *
 * const handleUpload = async () => {
 *   const result = await uploadFile(uploadId, file, 'Comment');
 *   if (result) {
 *     console.log('Uploaded:', result);
 *   }
 * };
 */
export const useFileUpload = (): IUseFileUploadReturn => {
  const dispatch = useAppDispatch();
  const [isUploading, setIsUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const cancelTokenRef = useRef<AbortController | null>(null);

  const uploadFile = useCallback(
    async (
      uploadId: string,
      file: File,
      comment?: string,
    ): Promise<IFile | null> => {
      // Reset state
      setIsUploading(true);
      setProgress(0);
      setError(null);

      // Create abort controller for cancellation
      cancelTokenRef.current = new AbortController();

      try {
        // Upload file via API with progress callback
        const result = await uploadFileToApi(
          { file, comment },
          // Progress callback: update Redux and local state
          (percent: number) => {
            setProgress(percent);
            dispatch(updateProgress({ uploadId, progress: percent }));
          },
          // Pass abort signal for cancellation
          cancelTokenRef.current?.signal,
        );

        dispatch(
          updateStatus({
            uploadId,
            status: "success" as UploadStatus,
            uploadedFileId: result.id,
          }),
        );

        return result;
      } catch (err) {
        // Handle cancellation separately
        if (err instanceof DOMException && err.name === "AbortError") {
          dispatch(
            updateStatus({
              uploadId,
              status: "error" as UploadStatus,
              error: "Загрузка отменена",
            }),
          );
          setError("Загрузка отменена");
          return null;
        }

        // Handle API errors
        let errorMessage = "Не удалось загрузить файл";

        if (err && typeof err === "object" && "message" in err) {
          const msg = (err as { message?: string }).message;
          if (msg) errorMessage = msg;
        }

        dispatch(
          updateStatus({
            uploadId,
            status: "error" as UploadStatus,
            error: errorMessage,
          }),
        );

        setError(errorMessage);
        return null;
      } finally {
        // Reset uploading state
        setIsUploading(false);
        cancelTokenRef.current = null;
      }
    },
    [dispatch],
  );

  /**
   * Cancel the current upload.
   */
  const cancelUpload = useCallback((): boolean => {
    if (!cancelTokenRef.current) return false;

    cancelTokenRef.current.abort();
    cancelTokenRef.current = null;
    setIsUploading(false);

    return true;
  }, []);

  return {
    isUploading,
    progress,
    error,
    uploadFile,
    cancelUpload,
  };
};
