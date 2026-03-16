import type { IconType } from "react-icons";
import {
  FaFileAudio,
  FaFileCode,
  FaFileImage,
  FaFileLines,
  FaFileVideo,
  FaFileZipper,
  FaFolder,
} from "react-icons/fa6";

import FILE_EXTENSIONS from "@/shared/configs/file-extensions.json";

import type { FileType } from "./types";

// =============================================================================
// FILE EXTENSIONS MAPPING
// =============================================================================

/** Maps file extension to file type */
const EXTENSION_TO_TYPE = new Map<string, FileType>();

Object.entries(FILE_EXTENSIONS).forEach(([type, extensions]) => {
  extensions.forEach((ext) => {
    EXTENSION_TO_TYPE.set(ext.toLowerCase(), type as FileType);
  });
});

// =============================================================================
// CONSTANTS
// =============================================================================

/** Localized labels for file types. */
const LABELS_RU: Record<FileType, string> = {
  image: "Изображение",
  video: "Видео",
  audio: "Аудио",
  document: "Документ",
  archive: "Архив",
  code: "Код",
  unknown: "Файл",
};

/** File type icons. */
export const FILE_TYPE_ICONS: Record<FileType, IconType> = {
  image: FaFileImage,
  video: FaFileVideo,
  audio: FaFileAudio,
  document: FaFileLines,
  archive: FaFileZipper,
  code: FaFileCode,
  unknown: FaFolder,
};

// =============================================================================
// FILE TYPE UTILS
// =============================================================================

/**
 * Determines the file type based on the file extension.
 *
 * @param filename - The name of the file including its extension.
 * @returns The corresponding `FileType` for the file's extension,
 *  or `"unknown"` if the extension is not recognized.
 *
 * @example
 * getFileType("document.pdf"); // Returns "pdf"
 * getFileType("image.jpg");    // Returns "image"
 * getFileType("script.exe");   // Returns "unknown"
 */
export const getFileType = (filename: string): FileType => {
  const extension = filename.split(".").pop()?.toLowerCase() || "";
  return EXTENSION_TO_TYPE.get(extension) || "unknown";
};

/**
 * Returns the localized (Russian) label for a given file type.
 *
 * @param type - The `FileType` enum value for which to retrieve the display
 *  label.
 * @returns A human-readable, localized string representing the file type.
 *
 * @example
 * getFileTypeLabel("image");   // Returns "Изображение"
 * getFileTypeLabel("video");   // Returns "Видео"
 * getFileTypeLabel("unknown"); // Returns "Файл"
 */
export const getFileTypeRuLabel = (type: FileType): string => LABELS_RU[type];
