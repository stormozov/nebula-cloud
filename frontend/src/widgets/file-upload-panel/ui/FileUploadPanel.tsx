import classNames from "classnames";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import {
  cancelUpload,
  clearCompleted,
  type IUploadFile,
  removeFile,
  retryUpload,
  selectCanClosePanel,
  selectIsPanelVisible,
  selectIsQueueCompleted,
  selectUploadQueue,
  selectUploadStats,
  setPanelVisible,
} from "@/entities/file-upload";
import { FileUploadItem } from "@/features/file/file-upload";
import { useAnimatedClose } from "@/shared/hooks";
import { Button, Icon } from "@/shared/ui";

import "./FileUploadPanel.scss";

/**
 * File upload panel widget.
 *
 * Displays all active and completed file uploads with progress tracking.
 * Positioned in bottom-right corner, appears automatically when uploads start.
 */
export function FileUploadPanel() {
  const dispatch = useAppDispatch();
  const queue = useAppSelector(selectUploadQueue);
  const isPanelVisible = useAppSelector(selectIsPanelVisible);
  const isQueueCompleted = useAppSelector(selectIsQueueCompleted);
  const canClosePanel = useAppSelector(selectCanClosePanel);
  const stats = useAppSelector(selectUploadStats);

  const { isClosing, handleCloseWithAnimation } = useAnimatedClose({
    onClose: () => {
      dispatch(setPanelVisible(false));
      dispatch(clearCompleted());
    },
    isBlocked: !canClosePanel,
    animationDuration: 300,
  });

  /**
   * Handle cancel upload button click.
   */
  const handleCancel = (uploadId: string): void => {
    dispatch(cancelUpload({ uploadId }));
  };

  const handleRetry = (uploadId: string): void => {
    dispatch(retryUpload({ uploadId }));
    console.warn("Retry upload:", uploadId);
  };

  const handleRemove = (uploadId: string): void => {
    dispatch(removeFile({ uploadId }));
  };

  const {
    success: completedCount,
    error: failedCount,
    uploading: uploadingCount,
  } = stats;

  /**
   * Get panel title based on queue state.
   */
  const getPanelTitle = (): string => {
    if (uploadingCount > 0) return `Загрузка (${uploadingCount})`;
    if (isQueueCompleted) return `Готово (${completedCount}/${queue.length})`;
    return `Файлы (${queue.length})`;
  };

  // Don't render if panel is hidden and queue is empty
  if (!isPanelVisible && queue.length === 0 && !isClosing) return null;

  return (
    <div
      className={classNames("file-upload-panel", {
        "file-upload-panel--visible": isPanelVisible,
        "file-upload-panel--closing": isClosing,
      })}
    >
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
          onClick={handleCloseWithAnimation}
          disabled={!canClosePanel}
          title={
            canClosePanel
              ? "Закрыть панель"
              : "Нельзя закрыть во время загрузки"
          }
          aria-label="Закрыть панель загрузок"
        >
          ✕
        </Button>
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
            className="file-upload-panel__clear-btn"
            onClick={handleCloseWithAnimation}
          >
            <Icon name="trash" />
            Очистить
          </Button>
        </footer>
      )}
    </div>
  );
}
