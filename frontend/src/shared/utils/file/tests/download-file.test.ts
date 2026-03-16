import { beforeEach, describe, expect, it, vi } from "vitest";

import { downloadFile } from "../download-file";

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Helper: creates a test blob with default content
 * Avoids duplication across tests
 */
const createTestBlob = (
  content: string = "test content",
  type: string = "text/plain",
): Blob => new Blob([content], { type });

/**
 * Helper: creates a mock anchor element that tracks property assignments
 * Properly structured to avoid happy-dom errors
 */
const createMockAnchor = () => {
  return {
    href: "",
    download: "",
    style: { display: "" },
    click: vi.fn(),
  } as unknown as HTMLAnchorElement;
};

/**
 * Helper: mocks DOM manipulation methods to avoid happy-dom errors with fake nodes
 */
const mockDomManipulation = () => {
  vi.spyOn(document.body, "appendChild").mockImplementation(
    (node: Node): Node => node,
  );
  vi.spyOn(document.body, "removeChild").mockImplementation(
    (node: Node): Node => node,
  );
};

// =============================================================================
// TEST SUITE
// =============================================================================

describe("download-file", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = "";
  });

  // ---------------------------------------------------------------------------
  //  Success scenarios
  // ---------------------------------------------------------------------------

  /**
   * Success scenarios - valid inputs with expected DOM operations
   */
  describe("success scenarios", () => {
    /**
     * @description Creates object URL from blob
     * @scenario Valid blob and filename provided
     * @expected URL.createObjectURL called with blob
     */
    it("should create object URL from blob", async () => {
      const blob = createTestBlob();
      const createSpy = vi
        .spyOn(URL, "createObjectURL")
        .mockReturnValue("blob:test");

      vi.spyOn(document, "createElement").mockReturnValue(createMockAnchor());
      mockDomManipulation();

      await downloadFile(blob, "test.txt");

      expect(createSpy).toHaveBeenCalledWith(blob);

      createSpy.mockRestore();
    });

    /**
     * @description Creates anchor with correct attributes
     * @scenario Valid blob and filename provided
     * @expected Anchor configured with URL, filename, and hidden style
     */
    it("should create anchor with correct attributes", async () => {
      const blob = createTestBlob();
      const filename = "document.pdf";
      const testUrl = "blob:test-url";
      const mockLink = createMockAnchor();

      vi.spyOn(URL, "createObjectURL").mockReturnValue(testUrl);
      vi.spyOn(document, "createElement").mockReturnValue(mockLink);
      mockDomManipulation();

      await downloadFile(blob, filename);

      expect(mockLink.href).toBe(testUrl);
      expect(mockLink.download).toBe(filename);
      expect(mockLink.style.display).toBe("none");
      expect(mockLink.click).toHaveBeenCalled();
    });

    /**
     * @description Revokes object URL after delay
     * @scenario Download triggered successfully
     * @expected URL.revokeObjectURL called after 100ms
     */
    it("should revoke object URL after delay", async () => {
      vi.useFakeTimers();
      const blob = createTestBlob();
      const testUrl = "blob:test-url";
      const revokeSpy = vi.spyOn(URL, "revokeObjectURL");

      vi.spyOn(URL, "createObjectURL").mockReturnValue(testUrl);
      vi.spyOn(document, "createElement").mockReturnValue(createMockAnchor());
      mockDomManipulation();

      await downloadFile(blob, "test.txt");

      expect(revokeSpy).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(100);

      expect(revokeSpy).toHaveBeenCalledWith(testUrl);

      vi.useRealTimers();
      revokeSpy.mockRestore();
    });

    /**
     * @description Handles different file types
     * @scenario Blob with various MIME types
     * @expected Download works regardless of blob type
     */
    it.each([
      { type: "text/plain", filename: "file.txt" },
      { type: "application/pdf", filename: "document.pdf" },
      { type: "image/png", filename: "image.png" },
      { type: "application/json", filename: "data.json" },
    ])("should handle $type files: $filename", async ({ type, filename }) => {
      const blob = createTestBlob("content", type);
      const mockLink = createMockAnchor();

      vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
      vi.spyOn(document, "createElement").mockReturnValue(mockLink);
      mockDomManipulation();

      await expect(downloadFile(blob, filename)).resolves.not.toThrow();

      expect(mockLink.download).toBe(filename);
    });

    /**
     * @description Handles special characters in filename
     * @scenario Filename contains spaces, unicode, or special chars
     * @expected Filename preserved in download attribute
     */
    it.each([
      { filename: "file with spaces.txt" },
      { filename: "файл.рус" },
      { filename: "file@#$%.pdf" },
      { filename: "very-long-filename-with-many-characters.txt" },
    ])("should handle special filename: '$filename'", async ({ filename }) => {
      const blob = createTestBlob();
      const mockLink = createMockAnchor();

      vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
      vi.spyOn(document, "createElement").mockReturnValue(mockLink);
      mockDomManipulation();

      await downloadFile(blob, filename);

      expect(mockLink.download).toBe(filename);
    });
  });

  // ---------------------------------------------------------------------------
  // Edge cases
  // ---------------------------------------------------------------------------

  /**
   * Edge cases - boundary values and timing behavior
   */
  describe("edge cases", () => {
    /**
     * @description Handles empty blob
     * @scenario Blob with zero bytes
     * @expected Download still triggers without errors
     */
    it("should handle empty blob", async () => {
      const blob = new Blob([], { type: "text/plain" });
      const mockLink = createMockAnchor();

      vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
      vi.spyOn(document, "createElement").mockReturnValue(mockLink);
      mockDomManipulation();

      await expect(downloadFile(blob, "empty.txt")).resolves.not.toThrow();
      expect(mockLink.download).toBe("empty.txt");
    });

    /**
     * @description Handles empty filename
     * @scenario Empty string passed as filename
     * @expected Download attribute set to empty string
     */
    it("should handle empty filename", async () => {
      const blob = createTestBlob();
      const mockLink = createMockAnchor();

      vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
      vi.spyOn(document, "createElement").mockReturnValue(mockLink);
      mockDomManipulation();

      await downloadFile(blob, "");
      expect(mockLink.download).toBe("");
    });

    /**
     * @description Cleanup timing is exactly 100ms
     * @scenario setTimeout scheduled for URL cleanup
     * @expected revokeObjectURL not called before 100ms, called at 100ms
     */
    it("should cleanup URL exactly after 100ms", async () => {
      vi.useFakeTimers();
      const blob = createTestBlob();
      const testUrl = "blob:test";
      const revokeSpy = vi.spyOn(URL, "revokeObjectURL");

      vi.spyOn(URL, "createObjectURL").mockReturnValue(testUrl);
      vi.spyOn(document, "createElement").mockReturnValue(createMockAnchor());
      mockDomManipulation();

      await downloadFile(blob, "test.txt");

      await vi.advanceTimersByTimeAsync(99);
      expect(revokeSpy).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1);
      expect(revokeSpy).toHaveBeenCalledWith(testUrl);

      vi.useRealTimers();
      revokeSpy.mockRestore();
    });
  });

  // ---------------------------------------------------------------------------
  // Failure scenarios
  // ---------------------------------------------------------------------------

  /**
   * Failure scenarios - error handling
   */
  describe("failure scenarios", () => {
    /**
     * @description Handles blob URL creation failure
     * @scenario URL.createObjectURL throws error
     * @expected Error propagates to caller
     */
    it("should propagate error if createObjectURL fails", async () => {
      const blob = createTestBlob();
      const error = new Error("URL creation failed");

      vi.spyOn(URL, "createObjectURL").mockImplementation(() => {
        throw error;
      });

      await expect(downloadFile(blob, "test.txt")).rejects.toThrow(
        "URL creation failed",
      );
    });

    /**
     * @description Handles DOM manipulation failure
     * @scenario document.body.appendChild throws error
     * @expected Error propagates
     */
    it("should propagate error if DOM manipulation fails", async () => {
      const blob = createTestBlob();
      const error = new Error("DOM manipulation failed");

      vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
      vi.spyOn(document, "createElement").mockReturnValue(createMockAnchor());
      vi.spyOn(document.body, "appendChild").mockImplementation(() => {
        throw error;
      });

      await expect(downloadFile(blob, "test.txt")).rejects.toThrow(
        "DOM manipulation failed",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Integration tests
  // ---------------------------------------------------------------------------

  /**
   * Integration tests
   */
  describe("integration", () => {
    /**
     * @description Full download flow
     * @scenario Real operations with mocked DOM
     * @expected All operations complete without errors
     */
    it("should complete full download flow", async () => {
      vi.useFakeTimers();
      const blob = createTestBlob("Hello, World!");
      const filename = "hello.txt";
      const testUrl = "blob:integration-test";
      const mockLink = createMockAnchor();

      const createSpy = vi
        .spyOn(URL, "createObjectURL")
        .mockReturnValue(testUrl);
      const revokeSpy = vi.spyOn(URL, "revokeObjectURL");
      vi.spyOn(document, "createElement").mockReturnValue(mockLink);
      mockDomManipulation();

      await downloadFile(blob, filename);

      expect(createSpy).toHaveBeenCalled();
      expect(mockLink.href).toBe(testUrl);
      expect(mockLink.download).toBe(filename);
      expect(mockLink.click).toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(100);
      expect(revokeSpy).toHaveBeenCalledWith(testUrl);

      vi.useRealTimers();
      createSpy.mockRestore();
      revokeSpy.mockRestore();
    });
  });
});
