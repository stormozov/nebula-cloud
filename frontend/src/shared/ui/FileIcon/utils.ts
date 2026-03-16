import FILE_EXTENSIONS from "@/shared/configs/file-extensions.json";

import type { FileType } from "./types";

/** Maps file extension to file type */
const EXTENSION_TO_TYPE = new Map<string, FileType>();

Object.entries(FILE_EXTENSIONS).forEach(([type, extensions]) => {
  extensions.forEach((ext) => {
    EXTENSION_TO_TYPE.set(ext.toLowerCase(), type as FileType);
  });
});

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
export const getFileTypeRuLabel = (type: FileType): string => {
  const labels: Record<FileType, string> = {
    image: "Изображение",
    video: "Видео",
    audio: "Аудио",
    document: "Документ",
    archive: "Архив",
    code: "Код",
    unknown: "Файл",
  };

  return labels[type];
};

/**
 * Returns an emoji symbol representing the given file type.
 *
 * @param type - The `FileType` enum value for which to retrieve
 *  the corresponding emoji symbol.
 * @returns A string containing an emoji that visually represents the file type.
 *
 * @example
 * getFileIconSymbol("image");   // Returns "🖼️"
 * getFileIconSymbol("document"); // Returns "📄"
 * getFileIconSymbol("unknown"); // Returns "📁"
 */
export const getFileIconSymbol = (type: FileType): string => {
  const symbols: Record<FileType, string> = {
    image: "🖼️",
    video: "🎬",
    audio: "🎵",
    document: "📄",
    archive: "📦",
    code: "💻",
    unknown: "📁",
  };

  return symbols[type];
};
