import { useEffect, useState } from "react";

import { useAppDispatch } from "@/app/store/hooks";
import {
  addFiles,
  generateUploadId,
  setDropzoneVisible,
} from "@/entities/file-upload";

import { fileStorage } from "../fileStorage";
import type { IUseGlobalDragDropProps } from "../types";
import { validateFileBatch } from "../validateFile";

/**
 * Custom React hook that enables global drag-and-drop functionality for file
 * uploads across the application.
 *
 * It listens to native drag events on the `document` and manages the visibility
 * of a dropzone UI component. When files are dropped, it validates them, stores
 * valid ones, and dispatches an action to initiate upload.
 *
 * @param {IUseGlobalDragDropProps} props - Configuration options for
 *  the drag-and-drop behavior.
 * @param {string} [props.comment] - Optional comment to attach to all uploaded
 *  files.
 * @param {boolean} [props.disabled=false] - If true, disables the drag-and-drop
 *  event listeners.
 *
 * @example
 * ```tsx
 * useGlobalDragDrop({ comment: "Uploaded via drag-drop", disabled: false });
 * ```
 */
export const useGlobalDragDrop = ({
  comment,
  disabled = false,
}: IUseGlobalDragDropProps = {}): void => {
  const dispatch = useAppDispatch();
  const [_, setDragCounter] = useState(0);

  useEffect(() => {
    if (disabled) return;

    // Handle drag events
    const handleDragEnter = (event: DragEvent): void => {
      event.preventDefault();

      setDragCounter((prev) => {
        const newCounter = prev + 1;

        if (prev === 0) {
          requestAnimationFrame(() => dispatch(setDropzoneVisible(true)));
        }

        return newCounter;
      });
    };

    const handleDragLeave = (event: DragEvent): void => {
      event.preventDefault();

      setDragCounter((prev) => {
        const newCounter = prev - 1;

        if (newCounter === 0) {
          requestAnimationFrame(() => dispatch(setDropzoneVisible(false)));
        }

        return Math.max(0, newCounter);
      });
    };

    const handleDragOver = (event: DragEvent): void => event.preventDefault();

    const handleDrop = (event: DragEvent): void => {
      event.preventDefault();

      setDragCounter(0);
      requestAnimationFrame(() => dispatch(setDropzoneVisible(false)));

      const files = Array.from(event.dataTransfer?.files || []);
      if (files.length === 0) return;

      // Validate files
      const validationResult = validateFileBatch(files);

      if (validationResult.invalidFiles.length > 0) {
        validationResult.invalidFiles.forEach(({ file, error }) => {
          console.error(`❌ Файл "${file.name}": ${error}`);
        });
        if (validationResult.validFiles.length === 0) return;
      }

      // Generate IDs and save File objects to storage
      const uploadIds: string[] = [];
      validationResult.validFiles.forEach((file) => {
        const uploadId = generateUploadId();
        uploadIds.push(uploadId);
        fileStorage.set(uploadId, file);
      });

      dispatch(
        addFiles({
          files: validationResult.validFiles,
          comment: comment || "",
          uploadIds,
        }),
      );
    };

    // Bind and unbind event listeners to the document
    const options = { capture: true };

    const bindEvent = <K extends keyof DocumentEventMap>(
      type: K,
      listener: (this: Document, ev: DocumentEventMap[K]) => void,
    ) => {
      document.addEventListener(type, listener, options);
      return () => document.removeEventListener(type, listener, options);
    };

    const unbindDragEnter = bindEvent("dragenter", handleDragEnter);
    const unbindDragLeave = bindEvent("dragleave", handleDragLeave);
    const unbindDragOver = bindEvent("dragover", handleDragOver);
    const unbindDrop = bindEvent("drop", handleDrop);

    return () => {
      unbindDragEnter();
      unbindDragLeave();
      unbindDragOver();
      unbindDrop();
      dispatch(setDropzoneVisible(false));
    };
  }, [dispatch, comment, disabled]);
};
