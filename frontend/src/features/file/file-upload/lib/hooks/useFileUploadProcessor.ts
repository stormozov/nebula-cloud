import { useEffect, useRef } from "react";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import { fileApi, uploadFile as uploadFileToApi } from "@/entities/file";
import { addFile } from "@/entities/file/model/slice";
import {
  selectActiveUpload,
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

        dispatch(
          addFile({
            id: result.id,
            originalName: result.originalName,
            comment: result.comment,
            size: result.size,
            sizeFormatted: result.sizeFormatted,
            uploadedAt: result.uploadedAt,
            lastDownloaded: result.lastDownloaded,
            hasPublicLink: result.hasPublicLink,
            publicLinkUrl: result.publicLinkUrl,
            downloadUrl: result.downloadUrl,
          }),
        );

        dispatch(fileApi.util.invalidateTags(["File"]));

        fileStorage.remove(activeUpload.id);
      } catch (error) {
        const errorMessage =
          error && typeof error === "object" && "message" in error
            ? (error as { message?: string }).message
            : "Не удалось загрузить файл";

        dispatch(
          updateStatus({
            uploadId: activeUpload.id,
            status: "error",
            error: errorMessage,
          }),
        );

        processedUploads.current.delete(activeUpload.id);

        console.error("Upload error:", error);
      }
    };

    processUpload();

    return () => {};
  }, [activeUpload, dispatch]);
};
