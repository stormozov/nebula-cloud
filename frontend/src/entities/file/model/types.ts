/**
 * File object returned by the API.
 *
 * Matches FileSerializer from backend.
 */
export interface IFile {
  id: number;
  originalName: string;
  comment: string | null;
  size: number;
  sizeFormatted: string;
  uploadedAt: string; // ISO 8601 date
  lastDownloaded: string | null;
  hasPublicLink: boolean;
  publicLinkUrl: string | null;
  downloadUrl: string;
}

/**
 * File upload payload (multipart/form-data).
 */
export interface IFileUpload {
  file: File; // Browser File object
  comment?: string;
}

/**
 * File rename payload.
 */
export interface IFileRename {
  originalName: string;
}

/**
 * File comment update payload.
 */
export interface IFileComment {
  comment: string;
}

/**
 * API response for file list.
 */
export type IFileListResponse = IFile[];

/**
 * File entity state in Redux store.
 */
export interface IFileState {
  fileList: IFile[];
  selectedFile: IFile | null;
  isLoading: boolean;
  error: string | null;
}
