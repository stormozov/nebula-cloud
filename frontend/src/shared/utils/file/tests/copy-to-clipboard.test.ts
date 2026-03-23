import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  copyToClipboard,
  copyToClipboardWithFeedback,
} from "../copy-to-clipboard";

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Helper: mocks `navigator.clipboard` with typed spy
 */
const mockClipboardAPI = (writeTextImpl: (text: string) => Promise<void>) => {
  const writeTextSpy = vi.fn<(text: string) => Promise<void>>(writeTextImpl);
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText: writeTextSpy } as unknown as Clipboard,
    writable: true,
    configurable: true,
  });
  return writeTextSpy;
};

/**
 * Helper: removes Clipboard API support to test legacy fallback
 */
const disableClipboardAPI = () => {
  Object.defineProperty(navigator, "clipboard", {
    value: undefined,
    writable: true,
    configurable: true,
  });
};

/**
 * Helper: mocks `document.execCommand` for legacy fallback tests
 *
 * `happy-dom` doesn't implement `execCommand` by default
 */
const mockExecCommand = (returnValue: boolean = true) => {
  const execCommandSpy = vi.fn<(command: string) => boolean>(() => returnValue);
  Object.defineProperty(document, "execCommand", {
    value: execCommandSpy,
    writable: true,
    configurable: true,
  });
  return execCommandSpy;
};

// =============================================================================
// TEST SUITE
// =============================================================================

describe("copy-to-clipboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = "";
    // Restore default clipboard state
    Object.defineProperty(navigator, "clipboard", {
      value: undefined,
      writable: true,
      configurable: true,
    });
    // Remove execCommand mock (will be added per-test if needed)
    Object.defineProperty(document, "execCommand", {
      value: undefined,
      writable: true,
      configurable: true,
    });
  });

  // ---------------------------------------------------------------------------
  //  Copy ti clipboard
  // ---------------------------------------------------------------------------

  /**
   * Tests for copyToClipboard function (main entry point)
   */
  describe("copyToClipboard", () => {
    /**
     * @description Uses modern Clipboard API when available
     * @scenario navigator.clipboard.writeText exists and succeeds
     * @expected Returns true, Clipboard API called with text
     */
    it("should use Clipboard API when available", async () => {
      const text = "test content";
      const writeTextSpy = mockClipboardAPI(async () => Promise.resolve());

      const result = await copyToClipboard(text);

      expect(result).toBe(true);
      expect(writeTextSpy).toHaveBeenCalledWith(text);
    });

    /**
     * @description Falls back to legacy when Clipboard API fails
     * @scenario navigator.clipboard.writeText throws error
     * @expected Falls back to execCommand, returns its result
     */
    it("should fallback to legacy when Clipboard API fails", async () => {
      const text = "test content";
      mockClipboardAPI(async () => Promise.reject(new Error("API error")));
      const execCommandSpy = mockExecCommand(true);

      const result = await copyToClipboard(text);

      expect(result).toBe(true);
      expect(execCommandSpy).toHaveBeenCalledWith("copy");
    });

    /**
     * @description Falls back to legacy when Clipboard API unavailable
     * @scenario navigator.clipboard is undefined
     * @expected Uses execCommand directly, returns its result
     */
    it("should use legacy when Clipboard API unavailable", async () => {
      const text = "test content";
      disableClipboardAPI();
      const execCommandSpy = mockExecCommand(true);

      const result = await copyToClipboard(text);

      expect(result).toBe(true);
      expect(execCommandSpy).toHaveBeenCalledWith("copy");
    });

    /**
     * @description Handles execCommand failure in legacy fallback
     * @scenario document.execCommand returns false
     * @expected Returns false
     */
    it("should return false when execCommand fails", async () => {
      const text = "test content";
      mockClipboardAPI(async () => Promise.reject(new Error("API error")));
      const execCommandSpy = mockExecCommand(false);

      const result = await copyToClipboard(text);

      expect(result).toBe(false);
      expect(execCommandSpy).toHaveBeenCalledWith("copy");
    });

    /**
     * @description Handles errors in legacy fallback gracefully
     * @scenario execCommand throws error during legacy copy
     * @expected Catches error, returns false
     */
    it("should handle errors in legacy fallback gracefully", async () => {
      const text = "test content";
      mockClipboardAPI(async () => Promise.reject(new Error("API error")));
      const execCommandSpy = vi.fn<(command: string) => boolean>(() => {
        throw new Error("execCommand error");
      });
      Object.defineProperty(document, "execCommand", {
        value: execCommandSpy,
        writable: true,
        configurable: true,
      });

      const result = await copyToClipboard(text);

      expect(result).toBe(false);
      expect(execCommandSpy).toHaveBeenCalledWith("copy");
    });

    /**
     * @description Handles various text content
     * @scenario Different text types and lengths
     * @expected Clipboard API called with exact text
     */
    it.each([
      { text: "simple text", desc: "plain text" },
      { text: "https://example.com/file/abc123", desc: "URL" },
      { text: "текст на русском", desc: "cyrillic" },
      { text: "special chars: @#$%^&*()", desc: "special characters" },
      { text: "", desc: "empty string" },
    ])("should handle $desc: '$text'", async ({ text }) => {
      const writeTextSpy = mockClipboardAPI(async () => Promise.resolve());
      await copyToClipboard(text);
      expect(writeTextSpy).toHaveBeenCalledWith(text);
    });
  });

  // ---------------------------------------------------------------------------
  //  Copy to clipboard with feedback
  // ---------------------------------------------------------------------------

  /**
   * Tests for copyToClipboardWithFeedback function
   * Focus: callback behavior only (copy logic tested above)
   */
  describe("copyToClipboardWithFeedback", () => {
    /**
     * @description Calls onSuccess callback on successful copy
     * @scenario copyToClipboard returns true, onSuccess provided
     * @expected onSuccess called once, onError not called
     */
    it("should call onSuccess on successful copy", async () => {
      const text = "test content";
      const onSuccess = vi.fn<() => void>();
      const onError = vi.fn<() => void>();

      mockClipboardAPI(async () => Promise.resolve());
      await copyToClipboardWithFeedback(text, onSuccess, onError);

      expect(onSuccess).toHaveBeenCalledTimes(1);
      expect(onError).not.toHaveBeenCalled();
    });

    /**
     * @description Calls onError callback on failed copy
     * @scenario copyToClipboard returns false, onError provided
     * @expected onError called once, onSuccess not called
     */
    it("should call onError on failed copy", async () => {
      const text = "test content";
      const onSuccess = vi.fn<() => void>();
      const onError = vi.fn<() => void>();

      disableClipboardAPI();
      mockExecCommand(false);
      await copyToClipboardWithFeedback(text, onSuccess, onError);

      expect(onSuccess).not.toHaveBeenCalled();
      expect(onError).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Handles optional callbacks gracefully
     * @scenario onSuccess/onError not provided or partially provided
     * @expected No errors, function completes normally
     */
    it.each([
      { desc: "no callbacks", onSuccess: undefined, onError: undefined },
      {
        desc: "only onSuccess",
        onSuccess: vi.fn<() => void>(),
        onError: undefined,
      },
      {
        desc: "only onError",
        onSuccess: undefined,
        onError: vi.fn<() => void>(),
      },
    ])("should handle $desc gracefully", async ({ onSuccess, onError }) => {
      const text = "test content";
      mockClipboardAPI(async () => Promise.resolve());

      await expect(
        copyToClipboardWithFeedback(text, onSuccess, onError),
      ).resolves.not.toThrow();
    });

    /**
     * @description Preserves text content through feedback wrapper
     * @scenario copyToClipboardWithFeedback called with text
     * @expected Underlying copyToClipboard receives exact text
     */
    it("should preserve text content through wrapper", async () => {
      const text = "https://example.com/file/abc123";
      const onSuccess = vi.fn<() => void>();
      const writeTextSpy = mockClipboardAPI(async () => Promise.resolve());

      await copyToClipboardWithFeedback(text, onSuccess);

      expect(writeTextSpy).toHaveBeenCalledWith(text);
      expect(onSuccess).toHaveBeenCalledTimes(1);
    });
  });
});
