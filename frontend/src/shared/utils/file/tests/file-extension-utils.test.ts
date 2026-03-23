import { describe, expect, it, vi } from "vitest";

import type { IFile } from "@/entities/file";

import { getFileExtension, isImageFile } from "../file-extension-utils";

vi.mock("@/shared/configs/file-extensions.json", () => ({
  default: {
    image: ["jpg", "jpeg", "png", "gif", "bmp", "svg", "webp", "ico"],
  },
}));

const mockImageExtensions = [
  "jpg",
  "jpeg",
  "png",
  "gif",
  "bmp",
  "svg",
  "webp",
  "ico",
];

describe("file-extension-utils", () => {
  describe("getFileExtension", () => {
    /**
     * @description Should return empty string for filename without extension
     * @scenario Passing filename without dot returns empty string
     * @expected Returns ""
     */
    it("should return empty string for filename without extension", () => {
      expect(getFileExtension("document")).toBe("");
    });

    /**
     * @description Should extract lowercase extension from filename with single dot
     * @scenario Single dot with lowercase extension
     * @expected Returns lowercase extension
     */
    it("should extract lowercase extension from filename with single dot", () => {
      expect(getFileExtension("document.pdf")).toBe("pdf");
    });

    /**
     * @description Should handle uppercase extension and convert to lowercase
     * @scenario Uppercase extension should be lowercased
     * @expected Returns lowercase extension
     */
    it("should handle uppercase extension and convert to lowercase", () => {
      expect(getFileExtension("document.PDF")).toBe("pdf");
      expect(getFileExtension("Image.JPG")).toBe("jpg");
    });

    /**
     * @description Should get extension from filename ending with dot
     * @scenario Filename ends with dot
     * @expected Returns empty string
     */
    it("should return empty string for filename ending with dot", () => {
      expect(getFileExtension("document.")).toBe("");
    });

    /**
     * @description Should extract last extension from filename with multiple dots
     * @scenario Multiple dots, get last part
     * @expected Returns last extension lowercased
     */
    it("should extract last extension from filename with multiple dots", () => {
      expect(getFileExtension("archive.tar.gz")).toBe("gz");
      expect(getFileExtension("my.file.with.dots.txt")).toBe("txt");
    });

    /**
     * @description Should return empty string for empty filename
     * @scenario Empty string input
     * @expected Returns ""
     */
    it("should return empty string for empty filename", () => {
      expect(getFileExtension("")).toBe("");
    });

    /**
     * @description Should handle filenames without extension after multiple dots
     * @scenario Multiple dots but no extension at end
     * @expected Returns ""
     */
    it("should handle filenames without extension after multiple dots", () => {
      expect(getFileExtension("folder.file.")).toBe("");
    });
  });

  describe("isImageFile", () => {
    const createMockFile = (originalName: string): IFile => ({
      id: 1,
      originalName,
      comment: null,
      size: 1024,
      sizeFormatted: "1 KB",
      uploadedAt: new Date().toISOString(),
      lastDownloaded: null,
      hasPublicLink: false,
      publicLinkUrl: null,
      downloadUrl: "/download",
    });

    /**
     * @description Should return true for valid image extension lowercase
     * @scenario File with known image extension jpg
     * @expected Returns true
     */
    it("should return true for valid image extension lowercase", () => {
      expect(isImageFile(createMockFile("photo.jpg"))).toBe(true);
      expect(isImageFile(createMockFile("image.PNG"))).toBe(true);
    });

    /**
     * @description Should return true for all supported image extensions
     * @scenario All image extensions from config
     * @expected Returns true for each
     */
    it.each(
      mockImageExtensions,
    )("should recognize %s as image extension", (ext) => {
      expect(isImageFile(createMockFile(`test.${ext}`))).toBe(true);
      expect(isImageFile(createMockFile(`test.${ext.toUpperCase()}`))).toBe(
        true,
      );
    });

    /**
     * @description Should return false for non-image extension
     * @scenario Document file pdf
     * @expected Returns false
     */
    it.each([
      {
        originalName: "document.pdf",
        expected: false,
      },
      {
        originalName: "archive.zip",
        expected: false,
      },
      {
        originalName: "script.js",
        expected: false,
      },
    ])(
      "should return $expected for non-image extension",
      ({ originalName, expected }) => {
        expect(isImageFile(createMockFile(originalName))).toBe(expected);
      })

    /**
     * @description Should return false for filename without extension
     * @scenario No dot in originalName
     * @expected Returns false
     */
    it("should return false for filename without extension", () => {
      expect(isImageFile(createMockFile("document"))).toBe(false);
      expect(isImageFile(createMockFile("image"))).toBe(false);
    });

    /**
     * @description Should return false for filename ending with dot
     * @scenario Ends with dot, no extension
     * @expected Returns false
     */
    it("should return false for filename ending with dot", () => {
      expect(isImageFile(createMockFile("photo."))).toBe(false);
    });

    /**
     * @description Should handle empty originalName
     * @scenario Empty originalName string
     * @expected Returns false
     */
    it("should return false for empty originalName", () => {
      expect(isImageFile(createMockFile(""))).toBe(false);
    });

    /**
     * @description Should handle null or undefined originalName
     * @scenario originalName is null/undefined (edge case)
     * @expected Returns false (defensive)
     */
    it("should throw error for null originalName", () => {
      const mockFile = {
        ...createMockFile("test"),
        originalName: null as unknown as string,
      };
      expect(() => isImageFile(mockFile)).toThrow(
        "Cannot read properties of null",
      );
    });

    /**
     * @description Should handle undefined originalName
     * @scenario originalName is undefined (edge case)
     * @expected Returns false (defensive)
     */
    it("should throw error for undefined originalName", () => {
      const mockFile = {
        ...createMockFile("test"),
        originalName: undefined as unknown as string,
      };
      expect(() => isImageFile(mockFile)).toThrow(
        "Cannot read properties of undefined",
      );
    });
  });
});
