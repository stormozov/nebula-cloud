import classNames from "classnames";
import { useEffect } from "react";
import { toast } from "react-toastify";

import type { IUploadFile } from "@/entities/file-upload";
import { FileUploadItem } from "@/features/file/file-upload";
import { Button, Icon } from "@/shared/ui";

import { useFileUploadPanel } from "../lib/useFileUploadPanel";

import "./FileUploadPanel.scss";

/**
 * File upload panel widget.
 *
 * Displays all active and completed file uploads with progress tracking.
 * Positioned in bottom-right corner, appears automatically when uploads start.
 */
export function FileUploadPanel() {
  const {
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
  } = useFileUploadPanel();

  const {
    success: completedCount,
    error: failedCount,
    uploading: uploadingCount,
  } = stats;

  useEffect(() => {
    if (isQueueCompleted) {
      if (failedCount > 0) {
        const storageError = queue.find((upload) => 
          upload.error?.includes('Превышен лимит хранилища')
        );
        if (storageError) {
          toast.error(storageError.error || 'Ошибка загрузки');
        } else {
          toast.error(`Ошибки загрузки файлов (${failedCount})`);
        }
      } else {
        toast.success("Файлы успешно загружены");
      }
    }
  }, [isQueueCompleted, failedCount, queue]);

  const getPanelTitle = (): string => {
    if (uploadingCount > 0) return `Загрузка (${uploadingCount})`;
    if (isQueueCompleted) return `Готово (${completedCount}/${queue.length})`;
    return `Файлы (${queue.length})`;
  };

  const panelClasses = classNames("file-upload-panel", {
    "file-upload-panel--visible": isPanelVisible,
    "file-upload-panel--closing": isClosing,
  });

  // Don't render if panel is hidden and queue is empty
  if (!isPanelVisible && queue.length === 0 && !isClosing) return null;

  return (
    <div className={panelClasses}>
      {/* Header */}
      <header className="file-upload-panel__header">
        <div className="file-upload-panel__title">
          {getPanelTitle()}
          {isQueueCompleted && <Icon name="check" color="success" />}
        </div>
        <Button
          type="button"
          variant="ghost"
          className="file-upload-panel__close-btn"
          icon={{ name: "close" }}
          onClick={handleCloseWithAnimation}
          disabled={!canClosePanel}
          title={
            canClosePanel
              ? "Закрыть панель"
              : "Нельзя закрыть во время загрузки"
          }
          aria-label="Закрыть панель загрузок"
        />
      </header>

      {/* Upload Queue List */}
      <div className="file-upload-panel__queue">
        <ul className="file-upload-panel__queue-list">
          {queue.map((upload: IUploadFile) => (
            <FileUploadItem
              key={upload.id}
              upload={upload}
              onCancel={handleCancel}
              onRetry={handleRetry}
              onRemove={handleRemove}
            />
          ))}
        </ul>
      </div>

      {/* Footer with statistics */}
      {queue.length > 0 && (
        <footer className="file-upload-panel__footer">
          <div className="file-upload-panel__stats">
            <span className="file-upload-panel__stat file-upload-panel__stat--success">
              <Icon name="check" color="success" />
              {completedCount}
            </span>
            {failedCount > 0 && (
              <span className="file-upload-panel__stat file-upload-panel__stat--error">
                <Icon name="close" color="error" />
                {failedCount}
              </span>
            )}
          </div>
          <Button
            type="button"
            variant="outline"
            size="small"
            icon={{ name: "trash" }}
            className="file-upload-panel__clear-btn"
            onClick={handleCloseWithAnimation}
          >
            Очистить
          </Button>
        </footer>
      )}
    </div>
  );
}
