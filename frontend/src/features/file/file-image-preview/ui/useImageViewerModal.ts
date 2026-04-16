import { useEffect, useRef, useState } from "react";

import { getImageBlobFromApi } from "@/entities/file";
import { useBodyScrollLock } from "@/shared/hooks";

import type { IImageViewerModalProps } from "./types";

/**
 * Return type of the `useImageViewerModal` hook.
 */
export interface IUseImageViewerModalReturns {
  /** Reference to the modal's root DOM element. */
  modalRef: React.RefObject<HTMLDivElement | null>;
  /** The URL of the image being displayed, or `null` if no image is loaded. */
  imageUrl: string | null;
  /** Indicates whether the image is currently being loaded. */
  loading: boolean;
  /** Error message if image loading failed, or `null` if there is no error. */
  error: string | null;
}

/**
 * Custom hook for managing the state and behavior of an image viewer modal.
 */
export const useImageViewerModal = ({
  isOpen,
  file,
  onClose,
}: IImageViewerModalProps): IUseImageViewerModalReturns => {
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const modalRef = useRef<HTMLDivElement>(null);
  const imageUrlRef = useRef<string | null>(null);

  useBodyScrollLock(isOpen);

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

  return {
    modalRef,
    imageUrl,
    loading,
    error,
  };
};
