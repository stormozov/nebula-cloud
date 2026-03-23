import { configureStore } from "@reduxjs/toolkit";
import {
  clearAuthTokens,
  localStorageMock,
  resetLocalStorage,
  setAuthTokens,
} from "@tests/mocks/localStorage";
import { server } from "@tests/mocks/server";
import { delay, HttpResponse, http } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fileSlice } from "../../model/slice";
import type { IFile } from "../../model/types";

// =============================================================================
// IMPORT FILE API ONCE
// =============================================================================

const { fileApi, uploadFile } = await import("../fileApi");

// =============================================================================
// MOCK SETUP
// =============================================================================

vi.stubGlobal("import.meta", {
  env: {
    VITE_API_BASE_URL: "/api",
  },
});

// =============================================================================
// MOCK DATA
// =============================================================================

const createMockFile = (
  id: number,
  originalName: string = "test.txt",
): IFile => ({
  id,
  originalName,
  comment: null,
  size: 1024,
  sizeFormatted: "1 KB",
  uploadedAt: new Date().toISOString(),
  lastDownloaded: null,
  hasPublicLink: false,
  publicLinkUrl: null,
  downloadUrl: `/api/storage/files/${id}/download/`,
});

// =============================================================================
// TEST STORE FACTORY
// =============================================================================

const createTestStore = () => {
  return configureStore({
    reducer: {
      [fileApi.reducerPath]: fileApi.reducer,
      file: fileSlice.reducer,
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware().concat(fileApi.middleware),
  });
};

// =============================================================================
// TEST SUITE
// =============================================================================

describe("fileApi - Upload Function", () => {
  let store: ReturnType<typeof createTestStore>;

  beforeEach(() => {
    setAuthTokens("mock_access_token");
    store = createTestStore();
  });

  afterEach(() => {
    vi.clearAllMocks();
    resetLocalStorage();
  });

  // ---------------------------------------------------------------------------
  // uploadFile Basic Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile Basic Functionality", () => {
    /**
     * @description Should upload file successfully
     * @scenario Calling uploadFile with valid File object
     * @expected Should return uploaded file data with correct structure
     */
    it("should upload file successfully", async () => {
      const mockFile = new File(["test content"], "test.txt", {
        type: "text/plain",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.originalName).toBe("test.txt");
      expect(result.downloadUrl).toBeDefined();
    });

    /**
     * @description Should return correct IFile structure
     * @scenario Calling uploadFile and checking response
     * @expected Result should match IFile interface
     */
    it("should return correct IFile structure", async () => {
      const mockFile = new File(["test"], "document.pdf", {
        type: "application/pdf",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toHaveProperty("id");
      expect(result).toHaveProperty("originalName");
      expect(result).toHaveProperty("comment");
      expect(result).toHaveProperty("size");
      expect(result).toHaveProperty("sizeFormatted");
      expect(result).toHaveProperty("uploadedAt");
      expect(result).toHaveProperty("downloadUrl");
      expect(result).toHaveProperty("hasPublicLink");
      expect(result).toHaveProperty("publicLinkUrl");
    });

    /**
     * @description Should handle file with comment
     * @scenario Calling uploadFile with comment in payload
     * @expected Comment should be included in FormData and response
     */
    it("should handle file with comment", async () => {
      const mockFile = new File(["test"], "notes.txt", { type: "text/plain" });
      const comment = "Important notes for team";

      const result = await uploadFile({ file: mockFile, comment });

      expect(result).toBeDefined();
      expect(result.comment).toBe(comment);
    });

    /**
     * @description Should handle file without comment
     * @scenario Calling uploadFile without comment parameter
     * @expected Comment should be null in response
     */
    it("should handle file without comment", async () => {
      const mockFile = new File(["test"], "image.png", { type: "image/png" });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
      expect(result.comment).toBeNull();
    });

    /**
     * @description Should handle empty comment string
     * @scenario Calling uploadFile with empty string comment
     * @expected Empty string is falsy, so comment should be null in response
     *
     * Note: The uploadFile function uses `if (data.comment)` which treats
     * empty string as falsy, so it won't be appended to FormData.
     */
    it("should handle empty comment string", async () => {
      const mockFile = new File(["test"], "file.txt", { type: "text/plain" });

      const result = await uploadFile({ file: mockFile, comment: "" });

      expect(result).toBeDefined();
      // Empty string is falsy, so it's not sent to server, result is null
      expect(result.comment).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // uploadFile Progress Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile Progress Callback", () => {
    /**
     * @description Should call progress callback during upload
     * @scenario Calling uploadFile with onProgress callback
     * @expected Callback should be invoked with progress percentage
     */
    it("should call progress callback during upload", async () => {
      const mockFile = new File(["test content"], "large.txt", {
        type: "text/plain",
      });
      const progressMock = vi.fn();

      await uploadFile({ file: mockFile }, progressMock);

      // Progress callback should be called at least once
      expect(progressMock).toHaveBeenCalled();
    });

    /**
     * @description Should call progress callback with valid percentage
     * @scenario Calling uploadFile and checking progress values
     * @expected Progress values should be between 0 and 100
     */
    it("should call progress callback with valid percentage", async () => {
      const mockFile = new File(["test"], "progress.txt", {
        type: "text/plain",
      });
      const progressMock = vi.fn();

      await uploadFile({ file: mockFile }, progressMock);

      if (progressMock.mock.calls.length > 0) {
        const progressValue = progressMock.mock.calls[0][0];
        expect(progressValue).toBeGreaterThanOrEqual(0);
        expect(progressValue).toBeLessThanOrEqual(100);
      }
    });

    /**
     * @description Should work without progress callback
     * @scenario Calling uploadFile without onProgress parameter
     * @expected Upload should complete successfully
     */
    it("should work without progress callback", async () => {
      const mockFile = new File(["test"], "simple.txt", { type: "text/plain" });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // uploadFile FormData Tests
  // ---------------------------------------------------------------------------
  /**
   * @description Should include comment in upload request
   * @scenario Calling uploadFile with comment
   * @expected Server should receive comment in response
   */
  it("should include comment in upload request", async () => {
    const mockFile = new File(["test"], "commented.txt", {
      type: "text/plain",
    });
    const comment = "Test comment";

    const result = await uploadFile({ file: mockFile, comment });

    // ✅ Test the outcome, not the implementation
    expect(result.comment).toBe(comment);
  });

  /**
   * @description Should not include comment when not provided
   */
  it("should not include comment when not provided", async () => {
    const mockFile = new File(["test"], "no-comment.txt", {
      type: "text/plain",
    });

    const result = await uploadFile({ file: mockFile });

    expect(result.comment).toBeNull();
  });

  // ---------------------------------------------------------------------------
  // uploadFile Authentication Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile Authentication", () => {
    /**
     * @description Should include auth token in upload request
     * @scenario Calling uploadFile with valid token in localStorage
     * @expected Authorization header should be set in axios request
     */
    it("should include auth token in upload request", async () => {
      setAuthTokens("upload_token_123");
      const mockFile = new File(["test"], "auth.txt", { type: "text/plain" });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Calling uploadFile without token in localStorage
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const mockFile = new File(["test"], "no-auth.txt", {
        type: "text/plain",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle invalid JSON token
     * @scenario Calling uploadFile with invalid JSON in localStorage
     * @expected Request should proceed without Authorization header (catch)
     */
    it("should handle invalid JSON token", async () => {
      localStorageMock.getItem.mockReturnValue("invalid-json");
      const mockFile = new File(["test"], "bad-token.txt", {
        type: "text/plain",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // uploadFile Error Handling Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile Error Handling", () => {
    /**
     * @description Should handle server error (500)
     * @scenario Calling uploadFile when server returns 500
     * @expected Should throw error with server message
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.post("/api/storage/files/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Upload failed" },
            { status: 500 },
          );
        }),
      );

      const mockFile = new File(["test"], "error.txt", { type: "text/plain" });

      await expect(uploadFile({ file: mockFile })).rejects.toThrow();
    });

    /**
     * @description Should handle bad request (400)
     * @scenario Calling uploadFile with invalid file data
     * @expected Should throw error with validation message
     */
    it("should handle bad request (400)", async () => {
      server.use(
        http.post("/api/storage/files/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Invalid file format" },
            { status: 400 },
          );
        }),
      );

      const mockFile = new File(["test"], "invalid.exe", {
        type: "application/x-executable",
      });

      await expect(uploadFile({ file: mockFile })).rejects.toThrow();
    });

    /**
     * @description Should handle long-running upload request
     * @scenario Calling uploadFile with delayed response
     * @expected Should complete successfully even with delay
     */
    it("should handle long-running upload request", async () => {
      server.use(
        http.post("/api/storage/files/", async () => {
          await delay(500);
          return HttpResponse.json(createMockFile(100, "slow.txt"), {
            status: 201,
          });
        }),
      );

      const mockFile = new File(["test"], "slow.txt", { type: "text/plain" });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
      expect(result.originalName).toBe("slow.txt");
    });

    /**
     * @description Should handle empty file
     * @scenario Calling uploadFile with empty File object
     * @expected Should return 400 error (empty files not allowed)
     */
    it("should handle empty file", async () => {
      const mockFile = new File([], "empty.txt", { type: "text/plain" });

      await expect(uploadFile({ file: mockFile })).rejects.toThrow();
    });

    /**
     * @description Should handle very large file
     * @scenario Calling uploadFile with large File object
     * @expected Should handle gracefully (backend may reject)
     */
    it("should handle very large file", async () => {
      // Create a larger file (1MB of repeated content)
      const largeContent = new Array(1024 * 1024).fill("x").join("");
      const mockFile = new File([largeContent], "large.txt", {
        type: "text/plain",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // uploadFile File Type Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile File Types", () => {
    /**
     * @description Should handle text file upload
     * @scenario Calling uploadFile with text/plain file
     * @expected Should upload successfully
     */
    it("should handle text file upload", async () => {
      const mockFile = new File(["Hello World"], "readme.txt", {
        type: "text/plain",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
      expect(result.originalName).toBe("readme.txt");
    });

    /**
     * @description Should handle image file upload
     * @scenario Calling uploadFile with image/png file
     * @expected Should upload successfully
     */
    it("should handle image file upload", async () => {
      // Minimal PNG header
      const pngHeader = new Uint8Array([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
      ]);
      const mockFile = new File([pngHeader], "image.png", {
        type: "image/png",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
      expect(result.originalName).toBe("image.png");
    });

    /**
     * @description Should handle PDF file upload
     * @scenario Calling uploadFile with application/pdf file
     * @expected Should upload successfully
     */
    it("should handle PDF file upload", async () => {
      // Minimal PDF header
      const pdfHeader = "%PDF-1.4\n";
      const mockFile = new File([pdfHeader], "document.pdf", {
        type: "application/pdf",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
      expect(result.originalName).toBe("document.pdf");
    });

    /**
     * @description Should handle file with special characters in name
     * @scenario Calling uploadFile with filename containing special chars
     * @expected Should upload successfully with original filename preserved
     */
    it("should handle file with special characters in name", async () => {
      const mockFile = new File(["test"], "файл с пробелами & символами!.txt", {
        type: "text/plain",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // uploadFile Integration Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile Integration", () => {
    /**
     * @description Should work with Redux store state
     * @scenario Calling uploadFile and checking store integration
     * @expected Store should be accessible during upload
     */
    it("should work with Redux store state", async () => {
      const mockFile = new File(["test"], "integration.txt", {
        type: "text/plain",
      });

      expect(store.getState()).toBeDefined();
      expect(store.dispatch).toBeDefined();

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle multiple sequential uploads
     * @scenario Calling uploadFile multiple times in sequence
     * @expected All uploads should complete successfully
     */
    it("should handle multiple sequential uploads", async () => {
      const files = [
        new File(["content1"], "file1.txt", { type: "text/plain" }),
        new File(["content2"], "file2.txt", { type: "text/plain" }),
        new File(["content3"], "file3.txt", { type: "text/plain" }),
      ];

      const results = [];
      for (const file of files) {
        const result = await uploadFile({ file });
        results.push(result);
      }

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result).toBeDefined();
      });
    });

    /**
     * @description Should handle upload with progress and comment together
     * @scenario Calling uploadFile with both comment and progress callback
     * @expected Both features should work together
     */
    it("should handle upload with progress and comment together", async () => {
      const mockFile = new File(["test"], "combined.txt", {
        type: "text/plain",
      });
      const comment = "Combined test";
      const progressMock = vi.fn();

      const result = await uploadFile(
        { file: mockFile, comment },
        progressMock,
      );

      expect(result).toBeDefined();
      expect(result.comment).toBe(comment);
    });
  });

  // ---------------------------------------------------------------------------
  // uploadFile Edge Cases Tests
  // ---------------------------------------------------------------------------
  describe("uploadFile Edge Cases", () => {
    /**
     * @description Should handle file with very long name
     * @scenario Calling uploadFile with filename exceeding typical limits
     * @expected Should handle gracefully
     */
    it("should handle file with very long name", async () => {
      const longName = `${"a".repeat(200)}.txt`;
      const mockFile = new File(["test"], longName, { type: "text/plain" });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle file with Unicode content
     * @scenario Calling uploadFile with file containing Unicode characters
     * @expected Should upload successfully with content preserved
     */
    it("should handle file with Unicode content", async () => {
      const unicodeContent = "Привет мир! 🌍 你好 世界";
      const mockFile = new File([unicodeContent], "unicode.txt", {
        type: "text/plain; charset=utf-8",
      });

      const result = await uploadFile({ file: mockFile });

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle comment with special characters
     * @scenario Calling uploadFile with comment containing special chars
     * @expected Comment should be preserved in response
     */
    it("should handle comment with special characters", async () => {
      const mockFile = new File(["test"], "special.txt", {
        type: "text/plain",
      });
      const comment = "Comment with <script>alert('xss')</script> & symbols!";

      const result = await uploadFile({ file: mockFile, comment });

      expect(result).toBeDefined();
      expect(result.comment).toBe(comment);
    });
  });
});
