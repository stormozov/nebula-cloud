import { createPortal } from "react-dom";

import { Button, Heading, Icon, Spinner } from "@/shared/ui";
import { truncateWithMiddleEllipsis } from "@/shared/utils";

import type { IImageViewerModalProps } from "./types";
import { useImageViewerModal } from "./useImageViewerModal";

import "./ImageViewerModal.scss";

/**
 * Modal for viewing an image.
 */
export function ImageViewerModal({
  isOpen,
  file,
  onClose,
}: IImageViewerModalProps) {
  const { modalRef, imageUrl, loading, error } = useImageViewerModal({
    isOpen,
    file,
    onClose,
  });

  if (!isOpen || !file) return null;

  const renderLoadingState = () => (
    <div className="image-viewer-modal__state">
      <Spinner color="tertiary" text="Загрузка изображения..." />
      <Button
        icon={{ name: "close" }}
        className="image-viewer-modal__loading-close"
        onClick={onClose}
      >
        Закрыть
      </Button>
    </div>
  );

  const renderErrorState = () => (
    <div className="image-viewer-modal__state">
      <Icon
        name="cloudBad"
        size={60}
        className="image-viewer-modal__error-icon"
      />
      <Heading level={3}>Не удалось загрузить изображение</Heading>
      <p>{error}</p>
      <Button icon={{ name: "close" }} onClick={onClose}>
        Закрыть
      </Button>
    </div>
  );

  const renderImage = () => {
    if (!imageUrl) return null;
    return (
      <>
        <button
          type="button"
          className="image-viewer-modal__close"
          onClick={onClose}
          aria-label="Закрыть просмотр"
        >
          <Icon name="close" size={16} />
        </button>

        <div className="image-viewer-modal__image-container">
          <img
            src={imageUrl}
            alt={file.originalName}
            className="image-viewer-modal__image"
          />
        </div>

        <div className="image-viewer-modal__footer">
          <span title={file.originalName}>
            {truncateWithMiddleEllipsis(file.originalName, 30)} (
            {file.sizeFormatted})
          </span>
        </div>
      </>
    );
  };

  const renderContent = () => {
    if (loading) return renderLoadingState();
    if (error) return renderErrorState();
    if (imageUrl) return renderImage();
    return null;
  };

  return createPortal(
    <div
      className="image-viewer-modal__overlay"
      role="dialog"
      aria-label={`Просмотр изображения ${file.originalName}`}
      ref={modalRef}
      tabIndex={-1}
    >
      <div className="image-viewer-modal__container">{renderContent()}</div>
    </div>,
    document.body,
  );
}
