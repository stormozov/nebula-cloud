import type { IFile } from "@/entities/file";

/**
 * Props for ImageViewerModal component.
 */
export interface IImageViewerModalProps {
  /** Whether the modal is open */
  isOpen: boolean;
  /** File to view */
  file: IFile | null;
  /** Callback to close the modal */
  onClose: () => void;
}
