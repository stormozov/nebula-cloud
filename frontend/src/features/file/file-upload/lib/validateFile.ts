import { getFileExtension } from "@/shared/utils";

import {
  ALLOWED_FILE_EXTENSIONS,
  MAX_FILE_SIZE,
  MAX_FILES_PER_BATCH,
  UPLOAD_ERROR_MESSAGES,
} from "./constants";
import type {
  IFileBatchValidationResult,
  IFileValidationResult,
} from "./types";

/**
 * Validates a single file.
 *
 * Checks:
 * - File is not empty
 * - File size does not exceed MAX_FILE_SIZE
 * - File extension is in ALLOWED_FILE_EXTENSIONS
 *
 * @param file - File object to validate
 * @returns Validation result with error message if invalid
 *
 * @example
 * const result = validateSingleFile(file);
 * if (!result.isValid) {
 *   showError(result.error);
 * }
 */
export const validateSingleFile = (file: File): IFileValidationResult => {
  // Check for empty file
  if (file.size === 0) {
    return {
      isValid: false,
      error: UPLOAD_ERROR_MESSAGES.EMPTY_FILE(file.name),
      file,
    };
  }

  // Check file size
  if (file.size > MAX_FILE_SIZE) {
    return {
      isValid: false,
      error: UPLOAD_ERROR_MESSAGES.FILE_TOO_LARGE(file.name),
      file,
    };
  }

  // Check file extension
  const extension = getFileExtension(file.name);
  if (!extension || !ALLOWED_FILE_EXTENSIONS.includes(extension)) {
    return {
      isValid: false,
      error: UPLOAD_ERROR_MESSAGES.INVALID_EXTENSION(file.name),
      file,
    };
  }

  return {
    isValid: true,
    file,
  };
};

/**
 * Validates a batch of files.
 *
 * Checks:
 * - Total number of files does not exceed MAX_FILES_PER_BATCH
 * - Each file passes single file validation
 *
 * @param files - Array of File objects to validate
 * @returns Batch validation result with valid and invalid files
 *
 * @example
 * const result = validateFileBatch(files);
 * if (!result.isValid) {
 *   result.invalidFiles.forEach(({ error }) => showError(error));
 * }
 * const validFiles = result.validFiles; // Ready for upload
 */
export const validateFileBatch = (
  files: File[],
): IFileBatchValidationResult => {
  const invalidFiles: IFileValidationResult[] = [];
  const validFiles: File[] = [];

  // Check total number of files
  if (files.length > MAX_FILES_PER_BATCH) {
    // Trim to max allowed (take first files up to limit)
    const trimmedFiles = files.slice(0, MAX_FILES_PER_BATCH);
    const excessFiles = files.slice(MAX_FILES_PER_BATCH);

    // Mark excess files as invalid
    excessFiles.forEach((file) => {
      invalidFiles.push({
        isValid: false,
        error: UPLOAD_ERROR_MESSAGES.TOO_MANY_FILES(files.length),
        file,
      });
    });

    // Validate only the allowed files
    trimmedFiles.forEach((file) => {
      const result = validateSingleFile(file);
      if (result.isValid) {
        validFiles.push(file);
      } else {
        invalidFiles.push(result);
      }
    });
  } else {
    // Validate each file individually
    files.forEach((file) => {
      const result = validateSingleFile(file);
      if (result.isValid) {
        validFiles.push(file);
      } else {
        invalidFiles.push(result);
      }
    });
  }

  return {
    isValid: invalidFiles.length === 0,
    validFiles,
    invalidFiles,
    errorCount: invalidFiles.length,
  };
};

/**
 * Validates file count only (for queue capacity check).
 *
 * Used to check if adding files would exceed queue limit.
 *
 * @param files - Array of File objects to validate
 * @param currentQueueLength - Current number of items in upload queue
 * @returns Whether files can be added to queue
 *
 * @example
 * const canAdd = validateFileCount(files, queue.length);
 * if (!canAdd) {
 *   showError('Сначала завершите текущие загрузки');
 * }
 */
export const validateFileCount = (
  files: File[],
  currentQueueLength: number,
): boolean => {
  return currentQueueLength + files.length <= MAX_FILES_PER_BATCH * 2;
};
