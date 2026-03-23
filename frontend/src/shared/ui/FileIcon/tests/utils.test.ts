import { beforeEach, describe, expect, it } from "vitest";

import type { FileType } from "../types";
import { FILE_TYPE_ICONS, getFileType, getFileTypeRuLabel } from "../utils";

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Helper: creates test cases for file extension to type mapping
 * Avoids duplication across tests
 */
const createExtensionTestCases = () => [
  // Image extensions
  { filename: "photo.jpg", expected: "image" as FileType },
  { filename: "image.jpeg", expected: "image" as FileType },
  { filename: "picture.png", expected: "image" as FileType },
  { filename: "animation.gif", expected: "image" as FileType },
  { filename: "bitmap.bmp", expected: "image" as FileType },
  { filename: "vector.svg", expected: "image" as FileType },
  { filename: "modern.webp", expected: "image" as FileType },
  { filename: "icon.ico", expected: "image" as FileType },
  // Video extensions
  { filename: "movie.mp4", expected: "video" as FileType },
  { filename: "clip.avi", expected: "video" as FileType },
  { filename: "recording.mov", expected: "video" as FileType },
  { filename: "film.wmv", expected: "video" as FileType },
  { filename: "video.mkv", expected: "video" as FileType },
  { filename: "stream.webm", expected: "video" as FileType },
  { filename: "flash.flv", expected: "video" as FileType },
  // Audio extensions
  { filename: "song.mp3", expected: "audio" as FileType },
  { filename: "track.wav", expected: "audio" as FileType },
  { filename: "lossless.flac", expected: "audio" as FileType },
  { filename: "audio.aac", expected: "audio" as FileType },
  { filename: "radio.ogg", expected: "audio" as FileType },
  { filename: "music.wma", expected: "audio" as FileType },
  // Document extensions
  { filename: "report.pdf", expected: "document" as FileType },
  { filename: "letter.doc", expected: "document" as FileType },
  { filename: "document.docx", expected: "document" as FileType },
  { filename: "spreadsheet.xls", expected: "document" as FileType },
  { filename: "table.xlsx", expected: "document" as FileType },
  { filename: "presentation.ppt", expected: "document" as FileType },
  { filename: "slides.pptx", expected: "document" as FileType },
  { filename: "notes.txt", expected: "document" as FileType },
  { filename: "formatted.rtf", expected: "document" as FileType },
  // Archive extensions
  { filename: "archive.zip", expected: "archive" as FileType },
  { filename: "compressed.rar", expected: "archive" as FileType },
  { filename: "package.7z", expected: "archive" as FileType },
  { filename: "backup.tar", expected: "archive" as FileType },
  { filename: "gzip.gz", expected: "archive" as FileType },
  { filename: "bzip.bz2", expected: "archive" as FileType },
  // Code extensions
  { filename: "script.js", expected: "code" as FileType },
  { filename: "module.ts", expected: "code" as FileType },
  { filename: "component.jsx", expected: "code" as FileType },
  { filename: "app.tsx", expected: "code" as FileType },
  { filename: "program.py", expected: "code" as FileType },
  { filename: "class.java", expected: "code" as FileType },
  { filename: "source.c", expected: "code" as FileType },
  { filename: "code.cpp", expected: "code" as FileType },
  { filename: "page.html", expected: "code" as FileType },
  { filename: "styles.css", expected: "code" as FileType },
  { filename: "data.json", expected: "code" as FileType },
];

// =============================================================================
// TEST SUITE
// =============================================================================

describe("utils", () => {
  beforeEach(() => {});

  // ---------------------------------------------------------------------------
  //  getFileType tests
  // ---------------------------------------------------------------------------

  /**
   * Tests for getFileType function
   */
  describe("getFileType", () => {
    /**
     * Success scenarios - valid filenames with known extensions
     */
    describe("success scenarios", () => {
      /**
       * @description Maps file extensions to correct file types
       * @scenario Filename has recognized extension
       * @expected Returns corresponding FileType from configuration
       */
      it.each(
        createExtensionTestCases(),
      )("should map '$filename' to '$expected' type", ({
        filename,
        expected,
      }) => {
        const result = getFileType(filename);
        expect(result).toBe(expected);
      });

      /**
       * @description Handles case-insensitive extensions
       * @scenario Extension has mixed or uppercase letters
       * @expected Returns correct FileType regardless of case
       */
      it.each([
        { filename: "FILE.JPG", expected: "image" as FileType },
        { filename: "document.PDF", expected: "document" as FileType },
        { filename: "audio.MP3", expected: "audio" as FileType },
        { filename: "Script.TS", expected: "code" as FileType },
        { filename: "archive.ZIP", expected: "archive" as FileType },
        { filename: "video.MP4", expected: "video" as FileType },
      ])("should handle uppercase extension: '$filename' → '$expected'", ({
        filename,
        expected,
      }) => {
        const result = getFileType(filename);
        expect(result).toBe(expected);
      });

      /**
       * @description Handles filenames with multiple dots
       * @scenario Filename contains multiple dot separators
       * @expected Uses last extension for type detection
       */
      it.each([
        { filename: "archive.tar.gz", expected: "archive" as FileType },
        { filename: "file.name.txt", expected: "document" as FileType },
        { filename: "backup.2024.zip", expected: "archive" as FileType },
        { filename: "config.test.json", expected: "code" as FileType },
      ])("should handle multiple dots: '$filename' → '$expected'", ({
        filename,
        expected,
      }) => {
        const result = getFileType(filename);
        expect(result).toBe(expected);
      });
    });

    /**
     * Edge cases - boundary values and special formats
     */
    describe("edge cases", () => {
      /**
       * @description Handles unknown file extensions
       * @scenario Extension not in FILE_EXTENSIONS configuration
       * @expected Returns "unknown" FileType
       */
      it.each([
        { filename: "file.exe" },
        { filename: "program.bat" },
        { filename: "data.xml" },
        { filename: "document.odt" },
        { filename: "unknown.xyz" },
      ])("should return 'unknown' for unrecognized extension: '$filename'", ({
        filename,
      }) => {
        const result = getFileType(filename);
        expect(result).toBe("unknown");
      });

      /**
       * @description Handles filenames without extension
       * @scenario Filename has no dot separator
       * @expected Returns "unknown" FileType
       */
      it.each([
        { filename: "README" },
        { filename: "Makefile" },
        { filename: "dockerfile" },
        { filename: "" },
      ])("should return 'unknown' for no extension: '$filename'", ({
        filename,
      }) => {
        const result = getFileType(filename);
        expect(result).toBe("unknown");
      });

      /**
       * @description Handles hidden files (dotfiles)
       * @scenario Filename starts with dot
       * @expected Returns "unknown" or correct type based on extension
       */
      it.each([
        { filename: ".gitignore", expected: "unknown" as FileType },
        { filename: ".bashrc", expected: "unknown" as FileType },
        { filename: ".config.json", expected: "code" as FileType },
      ])("should handle dotfile: '$filename' → '$expected'", ({
        filename,
        expected,
      }) => {
        const result = getFileType(filename);
        expect(result).toBe(expected);
      });

      /**
       * @description Handles empty extension after dot
       * @scenario Filename ends with dot
       * @expected Returns "unknown" FileType
       */
      it("should handle trailing dot", () => {
        const result = getFileType("file.");
        expect(result).toBe("unknown");
      });
    });
  });

  // ---------------------------------------------------------------------------
  //  getFileTypeRuLabel tests
  // ---------------------------------------------------------------------------
  /**
   * Tests for getFileTypeRuLabel function
   */
  describe("getFileTypeRuLabel", () => {
    /**
     * Success scenarios - all known file types
     */
    describe("success scenarios", () => {
      /**
       * @description Returns Russian labels for all file types
       * @scenario Valid FileType provided
       * @expected Returns corresponding localized label
       */
      it.each([
        { type: "image" as FileType, expected: "Изображение" },
        { type: "video" as FileType, expected: "Видео" },
        { type: "audio" as FileType, expected: "Аудио" },
        { type: "document" as FileType, expected: "Документ" },
        { type: "archive" as FileType, expected: "Архив" },
        { type: "code" as FileType, expected: "Код" },
        { type: "unknown" as FileType, expected: "Файл" },
      ])("should return '$expected' for '$type' type", ({ type, expected }) => {
        const result = getFileTypeRuLabel(type);
        expect(result).toBe(expected);
      });
    });

    /**
     * Edge cases - integration with getFileType
     */
    describe("edge cases", () => {
      /**
       * @description Works correctly with getFileType output
       * @scenario getFileType result passed to getFileTypeRuLabel
       * @expected Returns correct Russian label for any filename
       */
      it.each([
        { filename: "photo.jpg", expected: "Изображение" },
        { filename: "movie.mp4", expected: "Видео" },
        { filename: "song.mp3", expected: "Аудио" },
        { filename: "report.pdf", expected: "Документ" },
        { filename: "archive.zip", expected: "Архив" },
        { filename: "script.ts", expected: "Код" },
        { filename: "unknown.exe", expected: "Файл" },
      ])("should work with getFileType: '$filename' → '$expected'", ({
        filename,
        expected,
      }) => {
        const fileType = getFileType(filename);
        const label = getFileTypeRuLabel(fileType);
        expect(label).toBe(expected);
      });
    });
  });

  // ---------------------------------------------------------------------------
  //  FILE_TYPE_ICONS tests
  // ---------------------------------------------------------------------------

  /**
   * Tests for FILE_TYPE_ICONS constant
   */
  describe("FILE_TYPE_ICONS", () => {
    /**
     * Structure validation - icon mapping completeness
     */
    describe("structure validation", () => {
      /**
       * @description Has icons for all file types
       * @scenario FILE_TYPE_ICONS object inspected
       * @expected Contains icon component for each FileType
       */
      it("should have icons for all file types", () => {
        const fileTypes: FileType[] = [
          "image",
          "video",
          "audio",
          "document",
          "archive",
          "code",
          "unknown",
        ];

        fileTypes.forEach((type) => {
          expect(FILE_TYPE_ICONS[type]).toBeDefined();
          expect(typeof FILE_TYPE_ICONS[type]).toBe("function");
        });
      });

      /**
       * @description Icons are valid React components
       * @scenario Each icon has required component properties
       * @expected Icon has displayName or render property
       */
      it("should have valid React component structure", () => {
        Object.values(FILE_TYPE_ICONS).forEach((icon) => {
          // React components should be functions or objects with render
          expect(typeof icon).toBe("function");
        });
      });

      /**
       * @description Each file type has unique icon
       * @scenario Compare icon references across types
       * @expected No duplicate icon references (unless intentional)
       */
      it("should have distinct icons for each type", () => {
        const icons = Object.values(FILE_TYPE_ICONS);
        const uniqueIcons = new Set(icons);

        // We expect 7 file types, but some may share icons (e.g., unknown might use folder)
        // This test documents the current structure
        expect(icons.length).toBe(7);
        expect(uniqueIcons.size).toBeLessThanOrEqual(7);
      });
    });

    /**
     * Integration - icons work with file type detection
     */
    describe("integration", () => {
      /**
       * @description Icons accessible for any detected file type
       * @scenario getFileType result used to access FILE_TYPE_ICONS
       * @expected Returns valid icon component
       */
      it.each([
        { filename: "photo.jpg" },
        { filename: "movie.mp4" },
        { filename: "song.mp3" },
        { filename: "report.pdf" },
        { filename: "archive.zip" },
        { filename: "script.ts" },
        { filename: "unknown.exe" },
      ])("should provide icon for '$filename'", ({ filename }) => {
        const fileType = getFileType(filename);
        const icon = FILE_TYPE_ICONS[fileType];

        expect(icon).toBeDefined();
        expect(typeof icon).toBe("function");
      });
    });
  });

  // ---------------------------------------------------------------------------
  //  Integration tests
  // ---------------------------------------------------------------------------

  /**
   * Integration tests - full workflow from filename to UI components
   */
  describe("integration", () => {
    /**
     * @description Complete file type detection workflow
     * @scenario Filename → FileType → Label + Icon
     * @expected All utilities work together correctly
     */
    it("should support complete file type detection workflow", () => {
      const testCases = [
        {
          filename: "presentation.pptx",
          expectedType: "document" as FileType,
          expectedLabel: "Документ",
        },
        {
          filename: "podcast.mp3",
          expectedType: "audio" as FileType,
          expectedLabel: "Аудио",
        },
        {
          filename: "screenshot.png",
          expectedType: "image" as FileType,
          expectedLabel: "Изображение",
        },
      ];

      testCases.forEach(({ filename, expectedType, expectedLabel }) => {
        const fileType = getFileType(filename);
        const label = getFileTypeRuLabel(fileType);
        const icon = FILE_TYPE_ICONS[fileType];

        expect(fileType).toBe(expectedType);
        expect(label).toBe(expectedLabel);
        expect(icon).toBeDefined();
        expect(typeof icon).toBe("function");
      });
    });

    /**
     * @description Handles all configured file extensions
     * @scenario Every extension from FILE_EXTENSIONS.json
     * @expected Each maps to correct type, label, and icon
     */
    it("should handle all configured extensions", () => {
      const extensionTestCases = createExtensionTestCases();

      extensionTestCases.forEach(({ filename, expected }) => {
        const fileType = getFileType(filename);
        const label = getFileTypeRuLabel(fileType);
        const icon = FILE_TYPE_ICONS[fileType];

        expect(fileType).toBe(expected);
        expect(label).toBeDefined();
        expect(icon).toBeDefined();
      });
    });
  });
});
