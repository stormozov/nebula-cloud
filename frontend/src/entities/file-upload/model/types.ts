/**
 * Upload status for individual file in queue.
 */
export type UploadStatus = "pending" | "uploading" | "success" | "error";

/**
 * Upload file metadata.
 */
export interface IUploadFileMeta {
  /** File name (persisted) */
  name: string;
  /** File size in bytes (persisted) */
  size: number;
  /** File MIME type (persisted) */
  type: string;
  /** File last modified date (persisted) */
  lastModified: number;
  /** Optional comment for the file (persisted) */
  comment?: string;
}

/**
 * Individual file upload item in queue.
 */
export interface IUploadFile {
  /** Unique upload ID (generated client-side) */
  id: string;
  /** File metadata */
  file: IUploadFileMeta;
  /** Upload progress percentage (0-100) */
  progress: number;
  /** Current upload status */
  status: UploadStatus;
  /** Error message if status is 'error' */
  error?: string;
  /** Server file ID after successful upload */
  uploadedFileId?: number;
  /** Timestamp when upload started */
  startedAt?: number;
  /** Timestamp when upload completed */
  completedAt?: number;
  /** Flag: file needs re-upload after rehydration (File object lost) */
  needsReupload?: boolean;
}

/**
 * Upload queue state in Redux store.
 */
export interface IUploadState {
  /** Queue of files to upload */
  queue: IUploadFile[];
  /** Whether upload panel is visible */
  isPanelVisible: boolean;
  /** Whether global dropzone overlay is visible */
  isDropzoneVisible: boolean;
  /** ID of currently uploading file (null if idle) */
  activeUploadId: string | null;
  /** Total successfully uploaded files (session counter, persisted) */
  totalUploaded: number;
  /** Total failed uploads (session counter, persisted) */
  totalFailed: number;
  /** Flag: all uploads in current queue completed */
  isQueueCompleted: boolean;
}

/**
 * Payload for adding files to upload queue.
 */
export interface IAddFilesPayload {
  /** Files to upload */
  files: File[];
  /** Optional comment for all files */
  comment?: string;
}

/**
 * Payload for updating upload progress.
 */
export interface IUpdateProgressPayload {
  /** Upload ID */
  uploadId: string;
  /** Progress percentage (0-100) */
  progress: number;
}

/**
 * Payload for updating upload status.
 */
export interface IUpdateStatusPayload {
  /** Upload ID */
  uploadId: string;
  /** New status */
  status: UploadStatus;
  /** Error message if status is 'error' */
  error?: string;
  /** Server file ID if upload was successful */
  uploadedFileId?: number;
}

/**
 * Payload for removing file from queue.
 */
export interface IRemoveFilePayload {
  /** Upload ID */
  uploadId: string;
}

/**
 * Serialized upload file for persistence (without File object).
 */
export interface IUploadFileSerialized {
  /** Unique upload ID */
  id: string;
  /** File metadata */
  file: IUploadFileMeta;
  /** Upload progress percentage */
  progress: number;
  /** Current upload status */
  status: UploadStatus;
  /** Error message if status is 'error' */
  error?: string;
  /** Server file ID if upload was successful */
  uploadedFileId?: number;
  /** Timestamp when upload started */
  startedAt?: number;
  /** Timestamp when upload completed */
  completedAt?: number;
  /** Flag: file needs re-upload after rehydration */
  needsReupload?: boolean;
}
