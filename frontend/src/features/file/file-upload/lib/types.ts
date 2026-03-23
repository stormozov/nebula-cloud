import type { ReactNode } from "react";

import type { IFile } from "@/entities/file";
import type { IUploadFile } from "@/entities/file-upload";
import type { IButtonProps } from "@/shared/ui";

/**
 * File validation error codes for programmatic handling.
 */
export type FileValidationError =
  | "FILE_TOO_LARGE"
  | "INVALID_EXTENSION"
  | "TOO_MANY_FILES"
  | "EMPTY_FILE";

/**
 * Upload status for individual file in queue.
 */
type UploadProgressStatus = "pending" | "uploading" | "success" | "error";

/**
 * Validation result for a single file.
 */
export interface IFileValidationResult {
  /** Whether file passed validation */
  isValid: boolean;
  /** Error message if validation failed */
  error?: string;
  /** File that was validated */
  file: File;
}

/**
 * Validation result for a batch of files.
 */
export interface IFileBatchValidationResult {
  /** Whether all files passed validation */
  isValid: boolean;
  /** Valid files ready for upload */
  validFiles: File[];
  /** Invalid files with error messages */
  invalidFiles: IFileValidationResult[];
  /** Total error count */
  errorCount: number;
}

/**
 * Return type for useFileUpload hook.
 */
export interface IUseFileUploadReturn {
  /** Whether a file is currently being uploaded */
  isUploading: boolean;
  /** Current upload progress (0-100) */
  progress: number;
  /** Error message if upload failed */
  error: string | null;

  /**
   * Upload a file with progress tracking.
   *
   * @param uploadId - Upload ID from Redux queue
   * @param file - File object to upload
   * @param comment - Optional comment for the file
   *
   * @returns Promise resolving to uploaded file data from API
   */
  uploadFile: (
    /** Upload ID from Redux queue */
    uploadId: string,
    /** File object to upload */
    file: File,
    /** Optional comment for the file */
    comment?: string,
  ) => Promise<IFile | null>;

  /**
   * Cancel the current upload.
   * @returns Whether cancellation was successful
   */
  cancelUpload: () => boolean;
}

/**
 * Props for FileUploadItem component.
 */
export interface IFileUploadItemProps {
  /** Upload file data from Redux store. */
  upload: IUploadFile;
  /** Disable interactions (e.g., during upload). */
  disabled?: boolean;
  /** Callback when cancel is requested. */
  onCancel?: (uploadId: string) => void;
  /** Callback when retry is requested (for failed uploads). */
  onRetry?: (uploadId: string) => void;
  /** Callback when remove is requested (for completed uploads). */
  onRemove?: (uploadId: string) => void;
}

/**
 * Props for FileUploadProgress component.
 */
export interface IFileUploadProgressProps {
  /** Progress percentage (0-100). */
  progress: number;
  /** Upload status. */
  status: UploadProgressStatus;
}

/**
 * Props for FileUploadStatusIcon component.
 */
export interface IFileUploadStatusIconProps {
  /** Upload status. */
  status: UploadProgressStatus;
  /** Icon size in pixels. */
  size?: number;
}

/**
 * Props for the useGlobalDragDrop hook.
 */
export interface IUseGlobalDragDropProps {
  /** Optional comment to attach to all uploaded files */
  comment?: string;
  /** If true, disables the drag-and-drop event listeners */
  disabled?: boolean;
}

/**
 * Interface for queue state return values.
 */
export interface IUseFileUploadQueueReturn {
  /** Whether a file upload is currently in progress */
  isUploading: boolean;
  /** Total number of files in the queue */
  queueLength: number;
  /** Number of completed uploads */
  completedCount: number;
  /** Number of failed uploads */
  failedCount: number;
  /** Number of pending uploads */
  pendingCount: number;
}

/**
 * Props for FileUploadDropzone component.
 */
export interface IFileUploadDropzoneProps {
  /** Child components to render inside dropzone. */
  children?: ReactNode;
  /** Custom CSS class name. */
  className?: string;
  /** Default comment for uploaded files. */
  comment?: string;
  /** Accepted file types for file picker. */
  accept?: string;
  /** Disable dropzone interactions. */
  disabled?: boolean;
  /**
   * Enable click to open file picker (for local dropzone).
   * Global dropzone should set this to false.
   */
  clickable?: boolean;
  /** Allow multiple file selection. */
  multiple?: boolean;
  /** Mode: "local" for bounded zone, "global" for full-page overlay. */
  mode?: "local" | "global";
  /** Callback when files are successfully added to queue. */
  onFilesAdded?: (fileCount: number) => void;
  /** Callback when file validation fails. */
  onValidationError?: (errors: string[]) => void;
}

/**
 * Additional props for FileUploadButton component.
 */
export interface IFileUploadButtonAdditionalProps {
  /** Allow multiple file selection. */
  multiple?: boolean;
  /** Accepted file types for file picker. */
  accept?: string;
  /** Default comment for uploaded files. */
  comment?: string;
}

/**
 * Props for FileUploadButton component.
 */
export type IFileUploadButtonProps = IButtonProps &
  IFileUploadButtonAdditionalProps;
