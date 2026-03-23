import classNames from "classnames";
import { useCallback, useEffect, useRef, useState } from "react";

import { useAppDispatch } from "@/app/store/hooks";
import { addFiles, generateUploadId } from "@/entities/file-upload";

import { fileStorage } from "../../lib/fileStorage";
import type { IFileUploadDropzoneProps } from "../../lib/types";
import { validateFileBatch } from "../../lib/validateFile";
import { FileUploadButton } from "../FileUploadButton/FileUploadButton";

import "./FileUploadDropzone.scss";

/**
 * File upload dropzone component with Drag & Drop and click support.
 *
 * Provides a zone where users can drag and drop or click to select files.
 * Integrates with Redux store for upload queue management.
 *
 * @example
 * // Local dropzone with click support
 * <FileUploadDropzone mode="local" clickable={true}>
 *   <p>Перетащите файлы сюда или кликните для выбора</p>
 * </FileUploadDropzone>
 *
 * @example
 * // Global overlay dropzone (click disabled)
 * <FileUploadDropzone mode="global" clickable={false} />
 */
export function FileUploadDropzone({
  children,
  className,
  comment,
  accept,
  disabled = false,
  clickable = true,
  multiple = true,
  mode = "local",
  onFilesAdded,
  onValidationError,
}: IFileUploadDropzoneProps) {
  const dispatch = useAppDispatch();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragActive, setIsDragActive] = useState(false);
  const [_, setDragCounter] = useState(0);

  const isGlobalMode = mode === "global";

  /**
   * Process dropped or selected files.
   *
   * Validates files and adds them to upload queue.
   */
  const processFiles = useCallback(
    (files: File[]): void => {
      if (disabled || files.length === 0) return;

      // Validate files
      const { validFiles, invalidFiles } = validateFileBatch(files);

      // Handle validation errors
      if (invalidFiles.length > 0) {
        const errors = invalidFiles.map(({ error }) => error || "");
        onValidationError?.(errors);

        if (validFiles.length === 0) {
          setIsDragActive(false);
          setDragCounter(0);
          return;
        }
      }

      // Generate IDs ONCE and use for both storage and dispatch
      const uploadIds: string[] = [];
      validFiles.forEach((file) => {
        const uploadId = generateUploadId();
        uploadIds.push(uploadId);
        fileStorage.set(uploadId, file);
      });

      // Dispatch files with IDs
      dispatch(
        addFiles({
          files: validFiles,
          comment: comment || "",
          uploadIds,
        }),
      );

      // Notify parent component
      onFilesAdded?.(validFiles.length);

      // Reset drag state
      setIsDragActive(false);
      setDragCounter(0);
    },
    [dispatch, comment, disabled, onFilesAdded, onValidationError],
  );

  /**
   * Handle drag enter event.
   */
  const handleDragEnter = useCallback(
    (event: React.DragEvent<HTMLDivElement>): void => {
      if (isGlobalMode) return;

      event.preventDefault();
      event.stopPropagation();

      setDragCounter((prev) => prev + 1);
      setIsDragActive(true);
    },
    [isGlobalMode],
  );

  /**
   * Handle drag leave event.
   */
  const handleDragLeave = useCallback(
    (event: React.DragEvent<HTMLDivElement>): void => {
      if (isGlobalMode) return;

      event.preventDefault();
      event.stopPropagation();

      setDragCounter((prev) => {
        const newCounter = prev - 1;
        if (newCounter <= 0) {
          setIsDragActive(false);
          return 0;
        }
        return newCounter;
      });
    },
    [isGlobalMode],
  );

  /**
   * Handle drag over event.
   */
  const handleDragOver = useCallback(
    (event: React.DragEvent<HTMLDivElement>): void => {
      if (isGlobalMode) return;
      event.preventDefault();
      event.stopPropagation();
    },
    [isGlobalMode],
  );

  /**
   * Handle drop event.
   */
  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>): void => {
      event.preventDefault();
      event.stopPropagation();

      if (disabled || isGlobalMode) {
        setIsDragActive(false);
        setDragCounter(0);
        return;
      }

      processFiles([...event.dataTransfer.files]);
    },
    [disabled, isGlobalMode, processFiles],
  );

  /**
   * Handle click to open file picker.
   */
  const handleClick = useCallback((): void => {
    if (clickable && !disabled && fileInputRef.current) {
      fileInputRef.current.click();
    }
  }, [clickable, disabled]);

  /**
   * Handle file input change.
   */
  const handleFileChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>): void => {
      const files = event.target.files;
      if (!files || files.length === 0) return;

      processFiles([...files]);

      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    [processFiles],
  );

  /**
   * Handle key down event.
   */
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (clickable && !isGlobalMode && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      handleClick();
    }
  }, [clickable, isGlobalMode, handleClick]);

  /**
   * Reset drag state when component unmounts.
   */
  useEffect(() => {
    return () => {
      setIsDragActive(false);
      setDragCounter(0);
    };
  }, []);

  /**
   * Generate class names.
   */
  const classes = classNames(
    "file-upload-dropzone",
    {
      "file-upload-dropzone--active": isDragActive,
      "file-upload-dropzone--overlay": isGlobalMode,
      "file-upload-dropzone--clickable": clickable && !isGlobalMode,
    },
    className,
  );

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: <input> is used for file upload>
    // biome-ignore lint/a11y/useAriaPropsSupportedByRole: <input> is used for file upload>
    <div
      className={classes}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      onClick={handleClick}
      role={clickable && !isGlobalMode ? "button" : "region"}
      aria-label={
        isGlobalMode ? "Зона для перетаскивания файлов" : "Зона загрузки файлов"
      }
      aria-disabled={disabled}
      tabIndex={clickable && !isGlobalMode ? 0 : -1}
      onKeyDown={handleKeyDown}
    >
      {/* Hidden file input for click-to-upload */}
      {clickable && (
        <input
          ref={fileInputRef}
          type="file"
          className="file-upload-dropzone__input"
          onChange={handleFileChange}
          multiple={multiple}
          accept={accept}
          disabled={disabled}
          aria-label="Выберите файлы для загрузки"
          onClick={(e) => e.stopPropagation()}
        />
      )}

      {/* Content */}
      {children || (
        <div className="file-upload-dropzone__content">
          <div className="file-upload-dropzone__icon">
            {isGlobalMode ? "📥" : "📁"}
          </div>

          <div className="file-upload-dropzone__text">
            {isGlobalMode
              ? "Отпустите файлы для загрузки"
              : clickable
                ? "Перетащите файлы сюда или кликните для выбора"
                : "Перетащите файлы сюда"}
          </div>

          <div className="file-upload-dropzone__hint">
            Максимум 5 файлов, до 100 МБ каждый
          </div>

          <FileUploadButton
            variant="primary"
            size="small"
            onClick={handleClick}
            disabled={disabled}
          >
            Выбрать файлы
          </FileUploadButton>
        </div>
      )}
    </div>
  );
}
