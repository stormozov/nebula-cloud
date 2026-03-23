import type { IFile } from "@/entities/file";
import fileExtensions from "@/shared/configs/file-extensions.json";

/**
 * Gets file extension from filename (lowercase).
 */
export const getFileExtension = (filename: string): string => {
  const parts = filename.split(".");
  return parts.length > 1 ? parts.pop()?.toLowerCase() || "" : "";
};

/**
 * A set of valid image file extensions used to determine if a file is an image.
 */
const IMAGE_EXTENSIONS = new Set(fileExtensions.image as string[]);

/**
 * Checks whether the given file has an image file extension.
 *
 * @example
 * const file = { originalName: 'photo.jpg' };
 * console.log(isImageFile(file)); // true
 *
 * @example
 * const file = { originalName: 'document.pdf' };
 * console.log(isImageFile(file)); // false
 */
export function isImageFile(file: IFile): boolean {
  const extension = file.originalName.split(".").pop()?.toLowerCase();
  return extension ? IMAGE_EXTENSIONS.has(extension) : false;
}
