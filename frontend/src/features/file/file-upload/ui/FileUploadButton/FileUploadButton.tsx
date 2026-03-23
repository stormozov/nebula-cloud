import classNames from "classnames";
import { useCallback, useRef } from "react";

import { useAppDispatch } from "@/app/store/hooks";
import { addFiles, generateUploadId } from "@/entities/file-upload";
import { Button } from "@/shared/ui";

import { fileStorage } from "../../lib/fileStorage";
import type { IFileUploadButtonProps } from "../../lib/types";
import { validateFileBatch } from "../../lib/validateFile";

import "./FileUploadButton.scss";

/**
 * File upload button component.
 *
 * Opens native file picker dialog and adds validated files to upload queue.
 * Can be used on any page where file upload is needed.
 *
 * @example
 * <FileUploadButton variant="primary" size="large">
 *   Загрузить файл
 * </FileUploadButton>
 *
 * @example
 * <FileUploadButton
 *   variant="secondary"
 *   multiple={true}
 *   accept=".pdf,.doc,.docx"
 * >
 *   Загрузить документы
 * </FileUploadButton>
 */
export function FileUploadButton({
  children = "Загрузить файл",
  variant = "primary",
  size = "medium",
  fullWidth = false,
  multiple = true,
  className,
  accept,
  comment,
  disabled,
  ...restProps
}: IFileUploadButtonProps) {
  const dispatch = useAppDispatch();
  const fileInputRef = useRef<HTMLInputElement>(null);

  /**
   * Handle file input change.
   *
   * Validates files and adds them to upload queue.
   */
  const handleFileChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>): void => {
      const files = event.target.files;

      if (!files || files.length === 0) return;

      const fileArray = [...files];

      const validationResult = validateFileBatch(fileArray);

      if (validationResult.invalidFiles.length > 0) {
        validationResult.invalidFiles.forEach(({ file, error }) => {
          console.error(`❌ Файл "${file.name}": ${error}`);
        });

        if (validationResult.validFiles.length > 0) {
          console.warn(
            `📦 Загружаются ${validationResult.validFiles.length}`,
            `из ${fileArray.length} файлов`,
          );
        }
      }

      if (validationResult.validFiles.length === 0) {
        if (!fileInputRef.current) return;
        fileInputRef.current.value = "";
      }

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

      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    [dispatch, comment],
  );

  /**
   * Handle button click.
   *
   * Triggers hidden file input dialog.
   */
  const handleClick = useCallback((): void => {
    if (fileInputRef.current && !disabled) fileInputRef.current.click();
  }, [disabled]);

  return (
    <div className="file-upload-button">
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        className="file-upload-button__input"
        onChange={handleFileChange}
        multiple={multiple}
        accept={accept}
        disabled={disabled}
        aria-label="Выберите файлы для загрузки"
      />

      {/* Visible button */}
      <Button
        type="button"
        variant={variant}
        size={size}
        fullWidth={fullWidth}
        className={classNames("file-upload-button__btn", className)}
        onClick={handleClick}
        disabled={disabled}
        {...restProps}
      >
        {children}
      </Button>
    </div>
  );
}
