import { useCallback, useState } from "react";

import type { IFile } from "@/entities/file";

const MODAL_OPEN_DEFAULT_STATE = {
  delete: false,
  rename: false,
  comment: false,
  link: false,
  imageViewer: false,
};

/**
 * Union type representing all possible modal types in the file manager.
 */
export type ModalType =
  | "delete"
  | "rename"
  | "comment"
  | "link"
  | "imageViewer";

/**
 * Interface describing the return value of the `useFileManagerModals` hook.
 */
interface IUseFileManagerModalsReturns {
  /** Object tracking the open/closed state of each modal type. */
  modalOpen: Record<ModalType, boolean>;
  /** The currently selected file, used as context for most modals. */
  selectedFile: IFile | null;
  /**
   * The currently selected image file, specifically used for the image viewer
   * modal.
   */
  selectedImageFile: IFile | null;
  /**
   * Function to open a specific modal with a given file.
   *
   * @param type - The type of modal to open.
   * @param file - The file object to associate with the modal.
   */
  openModal: (type: ModalType, file: IFile) => void;
  /**
   * Function to close a specific modal.
   *
   * @param type - The type of modal to close.
   */
  closeModal: (type: ModalType) => void;
  /**
   * Function to update the selected image file for the image viewer.
   *
   * @param file - The image file to set, or null to clear.
   */
  setSelectedImageFile: (file: IFile | null) => void;
  /**
   * Function to update the selected file without opening a modal.
   *
   * @param file - The file to set as selected, or null to clear.
   */
  updateSelectedFile: (file: IFile | null) => void;
}

/**
 * Custom hook for managing modal states in the file manager.
 *
 * Handles the opening and closing of various modals and manages the selection
 * state of files. Provides functions to control modal visibility and file
 * selection throughout the file manager interface.
 */
export const useFileManagerModals = (): IUseFileManagerModalsReturns => {
  const [modalOpen, setModalOpen] = useState(MODAL_OPEN_DEFAULT_STATE);
  const [selectedFile, setSelectedFile] = useState<IFile | null>(null);
  const [selectedImageFile, setSelectedImageFile] = useState<IFile | null>(
    null,
  );

  const openModal = useCallback((type: ModalType, file: IFile) => {
    setSelectedFile(file);
    setModalOpen((prev) => ({ ...prev, [type]: true }));
  }, []);

  const closeModal = useCallback((type: ModalType) => {
    setModalOpen((prev) => ({ ...prev, [type]: false }));
    if (type !== "imageViewer") setSelectedFile(null);
  }, []);

  const updateSelectedFile = useCallback((file: IFile | null) => {
    setSelectedFile(file);
  }, []);

  return {
    modalOpen,
    selectedFile,
    selectedImageFile,
    openModal,
    closeModal,
    setSelectedImageFile,
    updateSelectedFile,
  };
};
