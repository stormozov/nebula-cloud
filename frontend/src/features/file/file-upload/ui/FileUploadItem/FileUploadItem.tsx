import fileUploadConfig from "@/shared/configs/file-upload.json";
import { formatFileSize } from "@/shared/utils";

import type { IFileUploadItemProps } from "../../lib/types";

import "./FileUploadItem.scss";
import { Button } from "@/shared/ui";

/**
 * File upload item component.
 *
 * Displays individual file upload status with progress bar,
 * status icon, and action buttons (cancel/retry/remove).
 *
 * @example
 * <FileUploadItem
 *   upload={upload}
 *   onCancel={handleCancel}
 *   onRetry={handleRetry}
 * />
 */
export function FileUploadItem({
  upload,
  onCancel,
  onRetry,
  onRemove,
  disabled = false,
}: IFileUploadItemProps) {
  const { id, file, progress, status, error, needsReupload } = upload;
  const { name: fileName, size: fileSize } = file;

  const formattedSize = formatFileSize(fileSize, 0);

  const STATUS_LABELS: Record<string, string> = fileUploadConfig.status_labels;

  /**
   * Handle cancel button click.
   */
  const handleCancel = (): void => {
    if (!disabled && onCancel) onCancel(id);
  };

  /**
   * Handle retry button click (for failed uploads).
   */
  const handleRetry = (): void => {
    if (!disabled && onRetry) onRetry(id);
  };

  /**
   * Handle remove button click (for completed uploads).
   */
  const handleRemove = (): void => {
    if (!disabled && onRemove) onRemove(id);
  };

  /**
   * Get status label for display.
   */
  const getStatusLabel = (): string => {
    return needsReupload ? "Требует загрузки" : STATUS_LABELS[status] || "";
  };

  /**
   * Get status CSS class modifier.
   */
  const getStatusClass = (): string => `file-upload-item--${status}`;

  return (
    <li className={`file-upload-item ${getStatusClass()}`}>
      {/* Status Icon */}
      <div className="file-upload-item__status">
        {status === "pending" && (
          <span className="file-upload-item__icon--pending">⏳</span>
        )}
        {status === "uploading" && (
          <span
            className="file-upload-item__icon--uploading"
            aria-hidden="true"
          >
            ↻
          </span>
        )}
        {status === "success" && (
          <span className="file-upload-item__icon--success">✓</span>
        )}
        {status === "error" && (
          <span className="file-upload-item__icon--error">✗</span>
        )}
      </div>

      {/* File Info */}
      <div className="file-upload-item__info">
        <div className="file-upload-item__name" title={fileName}>
          {fileName}
        </div>
        <div className="file-upload-item__meta">
          <span className="file-upload-item__size">{formattedSize}</span>
          <span className="file-upload-item__status-label">
            {getStatusLabel()}
          </span>
        </div>
      </div>

      {/* Progress Bar (only for uploading/pending) */}
      {(status === "uploading" || status === "pending") && (
        <div className="file-upload-item__progress">
          <div
            className="file-upload-item__progress-bar"
            style={{ width: `${progress}%` }}
            role="progressbar"
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`Прогресс загрузки: ${progress}%`}
          />
          {status === "uploading" && (
            <span className="file-upload-item__progress-text">{progress}%</span>
          )}
        </div>
      )}

      {/* Error Message (only for error status) */}
      {status === "error" && error && (
        <div className="file-upload-item__error" role="alert">
          {error}
        </div>
      )}

      {/* Action Buttons */}
      <div className="file-upload-item__actions">
        {status === "uploading" && (
          <Button
            type="button"
            className="file-upload-item__action-btn file-upload-item__action-btn--cancel"
            onClick={handleCancel}
            disabled={disabled}
            title="Отменить загрузку"
            aria-label="Отменить загрузку"
          >
            ✕
          </Button>
        )}

        {status === "error" && (
          <>
            <Button
              type="button"
              className="file-upload-item__action-btn file-upload-item__action-btn--retry"
              onClick={handleRetry}
              disabled={disabled || needsReupload}
              title="Повторить загрузку"
              aria-label="Повторить загрузку"
            >
              ↻
            </Button>
            <Button
              type="button"
              className="file-upload-item__action-btn file-upload-item__action-btn--remove"
              onClick={handleRemove}
              disabled={disabled}
              title="Удалить из списка"
              aria-label="Удалить из списка"
            >
              🗑️
            </Button>
          </>
        )}

        {status === "success" && (
          <Button
            type="button"
            variant="outline"
            size="small"
            className="file-upload-item__action-btn file-upload-item__action-btn--remove"
            onClick={handleRemove}
            disabled={disabled}
            title="Удалить из списка"
            aria-label="Удалить из списка"
          >
            🗑️
          </Button>
        )}
      </div>
    </li>
  );
}
