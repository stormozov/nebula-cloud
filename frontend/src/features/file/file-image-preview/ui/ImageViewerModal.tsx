import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AiOutlineClose } from "react-icons/ai";

import type { IFile } from "@/entities/file";
import { getImageBlobFromApi } from "@/entities/file";
import { Button } from "@/shared/ui";
import { truncateWithMiddleEllipsis } from "@/shared/utils";

import "./ImageViewerModal.scss";

/**
 * Props for ImageViewerModal component.
 */
interface IImageViewerModalProps {
  /** Whether the modal is open */
  isOpen: boolean;
  /** File to view */
  file: IFile | null;
  /** Callback to close the modal */
  onClose: () => void;
}

/**
 * Modal for viewing an image.
 */
export function ImageViewerModal({
  isOpen,
  file,
  onClose,
}: IImageViewerModalProps) {
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const modalRef = useRef<HTMLDivElement>(null);
  const imageUrlRef = useRef<string | null>(null);

  useEffect(() => {
    if (!isOpen || !file) {
      setImageUrl(null);
      setError(null);
      return;
    }

    const fetchImage = async () => {
      try {
        setLoading(true);
        setError(null);
        const blob = await getImageBlobFromApi(file.id);
        const url = URL.createObjectURL(blob);
        imageUrlRef.current = url;
        setImageUrl(url);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load image");
      } finally {
        setLoading(false);
      }
    };

    fetchImage();

    return () => {
      if (imageUrlRef.current) {
        URL.revokeObjectURL(imageUrlRef.current);
        imageUrlRef.current = null;
      }
    };
  }, [isOpen, file]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen && modalRef.current) modalRef.current.focus();
  }, [isOpen]);

  if (!isOpen || !file) return null;

  return createPortal(
    <div
      className="image-viewer-modal__overlay"
      role="dialog"
      aria-label={`Просмотр изображения ${file.originalName}`}
      ref={modalRef}
      tabIndex={-1}
    >
      <div className="image-viewer-modal__container">
        {error ? (
          <div className="image-viewer-modal__error">
            <h3>Ошибка загрузки изображения</h3>
            <p>{error}</p>
            <Button onClick={onClose}>
              <AiOutlineClose />
              Закрыть
            </Button>
          </div>
        ) : loading ? (
          <div className="image-viewer-modal__loading">
            Загрузка изображения...
          </div>
        ) : imageUrl ? (
          <>
            <button
              type="button"
              className="image-viewer-modal__close"
              onClick={onClose}
              aria-label="Закрыть просмотр"
            >
              <AiOutlineClose size={16} />
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
        ) : null}
      </div>
    </div>,
    document.body,
  );
}
