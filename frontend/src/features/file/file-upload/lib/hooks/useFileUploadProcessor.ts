import { useEffect, useRef } from "react";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import { uploadFile as uploadFileToApi } from "@/entities/file";
import {
  selectActiveUpload,
  setNeedsReupload,
  updateProgress,
  updateStatus,
} from "@/entities/file-upload";

import { fileStorage } from "../fileStorage";

/**
 * Custom hook that processes upload queue.
 *
 * Watches for active uploads and triggers actual file upload to server.
 *
 * This hook should be used once at the application level (e.g., in App.tsx)
 * to ensure all uploads are processed regardless of which page is active.
 *
 * @example
 * // In App.tsx
 * function App() {
 *   useFileUploadProcessor();
 *   return <Provider>...</Provider>;
 * }
 */
export const useFileUploadProcessor = (): void => {
  const dispatch = useAppDispatch();
  const activeUpload = useAppSelector(selectActiveUpload);

  const processedUploads = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!activeUpload || activeUpload.status !== "uploading") return;
    if (processedUploads.current.has(activeUpload.id)) return;

    processedUploads.current.add(activeUpload.id);

    // Get File object from storage
    const file = fileStorage.get(activeUpload.id);
    if (!file) {
      dispatch(
        updateStatus({
          uploadId: activeUpload.id,
          status: "error",
          error: "Файл не найден в памяти",
        }),
      );
      dispatch(setNeedsReupload({ uploadId: activeUpload.id }));
      processedUploads.current.delete(activeUpload.id);
      return;
    }

    // Trigger actual upload
    const processUpload = async () => {
      try {
        const result = await uploadFileToApi(
          { file, comment: activeUpload.file.comment },
          (progress) => {
            dispatch(updateProgress({ uploadId: activeUpload.id, progress }));
          },
        );

        dispatch(
          updateStatus({
            uploadId: activeUpload.id,
            status: "success",
            uploadedFileId: result.id,
          }),
        );

        fileStorage.remove(activeUpload.id);
      } catch (err) {
        const errorMessage =
          err && typeof err === "object" && "message" in err
            ? (err as { message?: string }).message
            : "Не удалось загрузить файл";

        dispatch(
          updateStatus({
            uploadId: activeUpload.id,
            status: "error",
            error: errorMessage,
          }),
        );

        processedUploads.current.delete(activeUpload.id);

        if (
          err &&
          typeof err === "object" &&
          "status" in err &&
          err.status === 401
        ) {
          return;
        }

        console.error("Upload error:", err);
      }
    };

    processUpload();

    return () => {};
  }, [activeUpload, dispatch]);
};
