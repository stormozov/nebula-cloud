import fileUploadConfig from "@/shared/configs/file-upload.json";
import { Button, Icon } from "@/shared/ui";
import { formatFileSize, truncateWithMiddleEllipsis } from "@/shared/utils";

import type { IFileUploadItemProps } from "../../lib/types";

import "./FileUploadItem.scss";

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

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // RENDERS
  // ---------------------------------------------------------------------------

  const renderStatusIcon = () => {
    switch (status) {
      case "uploading":
        return (
          <Icon
            name="retry"
            color="primary"
            className="file-upload-item__icon--uploading"
          />
        );
      case "success":
        return <Icon name="check" color="success" />;
      case "error":
        return <Icon name="close" color="error" />;
      default:
        return null;
    }
  };

  const renderInfoBlock = () => {
    return (
      <>
        <div className="file-upload-item__name" title={fileName}>
          {truncateWithMiddleEllipsis(fileName, 35)}
        </div>
        <div className="file-upload-item__meta">
          <span className="file-upload-item__size">{formattedSize}</span>
          <span className="file-upload-item__status-label">
            {getStatusLabel()}
          </span>
        </div>
      </>
    );
  };

  const renderProgressBar = () => {
    if (status !== "uploading") return null;
    return (
      <div className="file-upload-item__progress">
        <div className="file-upload-item__progress-bar">
          <div
            className="file-upload-item__progress-fill"
            style={{ width: `${progress}%` }}
          />
        </div>
        {status === "uploading" && (
          <span className="file-upload-item__progress-text">{progress}%</span>
        )}
      </div>
    );
  };

  const renderError = () => {
    if (status !== "error") return null;
    return (
      <div className="file-upload-item__error" role="alert">
        {error}
      </div>
    );
  };

  const renderRemoveButton = () => {
    return (
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
        <Icon name="trash" color="error" />
      </Button>
    );
  };

  const renderActionButtons = () => {
    if (status === "uploading") {
      return (
        <Button
          type="button"
          className="file-upload-item__action-btn file-upload-item__action-btn--cancel"
          onClick={handleCancel}
          disabled={disabled}
          title="Отменить загрузку"
          aria-label="Отменить загрузку"
        >
          <Icon name="close" color="error" />
        </Button>
      );
    }
    if (status === "error") {
      return (
        <>
          <Button
            type="button"
            className="file-upload-item__action-btn file-upload-item__action-btn--retry"
            onClick={handleRetry}
            disabled={disabled || needsReupload}
            title="Повторить загрузку"
            aria-label="Повторить загрузку"
          >
            <Icon name="retry" color="primary" />
          </Button>
          {renderRemoveButton()}
        </>
      );
    }
    if (status === "success") return renderRemoveButton();
  };

  return (
    <li className={`file-upload-item ${getStatusClass()}`}>
      <div className="file-upload-item__status">{renderStatusIcon()}</div>
      <div className="file-upload-item__info">{renderInfoBlock()}</div>
      {renderProgressBar()}
      {renderError()}
      <div className="file-upload-item__actions">{renderActionButtons()}</div>
    </li>
  );
}
