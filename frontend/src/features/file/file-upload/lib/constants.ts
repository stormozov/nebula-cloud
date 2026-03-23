import FILE_EXTENSIONS from "@/shared/configs/file-extensions.json";
import fileUploadConfig from "@/shared/configs/file-upload.json";
import { formatFileSize } from "@/shared/utils";

/**
 * Maximum file size in bytes.
 */
export const MAX_FILE_SIZE = fileUploadConfig.max_size * 1024 * 1024;

/**
 * Maximum number of files per upload batch.
 */
export const MAX_FILES_PER_BATCH = fileUploadConfig.max_files_per_batch;

/**
 * List of allowed file extensions.
 */
export const ALLOWED_FILE_EXTENSIONS = Object.values(
  FILE_EXTENSIONS,
).flat() as string[];

/**
 * Human-readable file size limit for error messages.
 */
export const MAX_FILE_SIZE_FORMATTED = formatFileSize(MAX_FILE_SIZE, 0);

/**
 * Error message templates.
 */
export const UPLOAD_ERROR_MESSAGES = {
  FILE_TOO_LARGE: (fileName: string) =>
    `Файл "${fileName}" превышает максимальный размер (${MAX_FILE_SIZE_FORMATTED})`,
  INVALID_EXTENSION: (fileName: string) =>
    `Файл "${fileName}" имеет недопустимый формат`,
  TOO_MANY_FILES: (count: number) =>
    `Выбрано файлов: ${count}. Максимум разрешено: ${MAX_FILES_PER_BATCH}`,
  EMPTY_FILE: (fileName: string) => `Файл "${fileName}" пустой`,
} as const;
