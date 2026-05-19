import { renderHook, act } from "@testing-library/react";
import { toast } from "react-toastify";
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import React from "react";

import { useBadgeCopy } from "../useBadgeCopy";
import { copyToClipboardWithFeedback } from "@/shared/utils";

vi.mock("@/shared/utils", () => ({
  copyToClipboardWithFeedback: vi.fn(),
}));

vi.mock("react-toastify", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

describe("useBadgeCopy", () => {
  let mockCopyToClipboard: Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCopyToClipboard = copyToClipboardWithFeedback as Mock;
    mockCopyToClipboard.mockResolvedValue(undefined);
  });

  describe("handleCopy", () => {
    /**
     * @description Should not call copyToClipboardWithFeedback when copyable is false
     * @scenario copyable = false, dot = false, displayContent = "5", children = 5
     * @expected copyToClipboardWithFeedback not called
     */
    it("should not copy when copyable is false", async () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(false, false, "5", 5));

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(mockCopyToClipboard).not.toHaveBeenCalled();
    });

    /**
     * @description Should not call copyToClipboardWithFeedback when dot is true (even if copyable is true)
     * @scenario copyable = true, dot = true, displayContent = "5", children = 5
     * @expected copyToClipboardWithFeedback not called
     */
    it("should not copy when dot is true", async () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(true, true, "5", 5));

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(mockCopyToClipboard).not.toHaveBeenCalled();
    });

    /**
     * @description Should copy displayContent when it is a string and copyable true / dot false
     * @scenario copyable = true, dot = false, displayContent = "99+", children = 100
     * @expected copyToClipboardWithFeedback called with "99+"
     */
    it("should copy displayContent string when displayContent is string", async () => {
      // Arrange
      const displayContent = "99+";
      const children = 100;
      const { result } = renderHook(() =>
        useBadgeCopy(true, false, displayContent, children),
      );

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalledWith(
        displayContent,
        expect.any(Function),
        expect.any(Function),
      );
    });

    /**
     * @description Should convert children to string when displayContent is not a string
     * @scenario copyable = true, dot = false, displayContent = React element, children = 42
     * @expected copyToClipboardWithFeedback called with String(children) = "42"
     */
    it("should copy children as string when displayContent is not a string", async () => {
      // Arrange
      const displayContent = React.createElement("div", null, "icon");
      const children = 42;
      const { result } = renderHook(() =>
        useBadgeCopy(true, false, displayContent, children),
      );

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalledWith(
        "42",
        expect.any(Function),
        expect.any(Function),
      );
    });

    /**
     * @description Should copy empty string when children is falsy (null/undefined) and displayContent not a string
     * @scenario copyable = true, dot = false, displayContent = null, children = null
     * @expected copyToClipboardWithFeedback called with ""
     */
    it("should copy empty string when children is null", async () => {
      // Arrange
      const { result } = renderHook(() =>
        useBadgeCopy(true, false, null, null),
      );

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalledWith(
        "",
        expect.any(Function),
        expect.any(Function),
      );
    });

    /**
     * @description Should show success toast when copy succeeds
     * @scenario copyToClipboardWithFeedback resolves, onCopySuccess called
     * @expected toast.success called with "Скопировано в буфер обмена"
     */
    it("should show success toast on successful copy", async () => {
      // Arrange
      mockCopyToClipboard.mockImplementation((_text, onSuccess, _onError) =>
        onSuccess(),
      );
      const { result } = renderHook(() =>
        useBadgeCopy(true, false, "test", "test"),
      );

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(toast.success).toHaveBeenCalledWith("Скопировано в буфер обмена", {
        autoClose: 2000,
      });
    });

    /**
     * @description Should show error toast when copy fails
     * @scenario copyToClipboardWithFeedback calls onError
     * @expected toast.error called with "Не удалось скопировать в буфер обмена"
     */
    it("should show error toast on copy failure", async () => {
      // Arrange
      mockCopyToClipboard.mockImplementation((_text, _onSuccess, onError) =>
        onError(),
      );
      const { result } = renderHook(() =>
        useBadgeCopy(true, false, "test", "test"),
      );

      // Act
      await act(async () => {
        await result.current.handleCopy();
      });

      // Assert
      expect(toast.error).toHaveBeenCalledWith(
        "Не удалось скопировать в буфер обмена",
        { autoClose: 2000 },
      );
    });
  });

  describe("handleKeyDown", () => {
    /**
     * @description Should not call handleCopy when key is Enter but copyable is false
     * @scenario copyable = false, event with key "Enter", handleKeyDown triggered
     * @expected handleCopy not called (copyToClipboard not called)
     */
    it("should not copy on Enter when copyable is false", () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(false, false, "5", 5));
      const event = new KeyboardEvent("keydown", { key: "Enter" });
      const reactEvent = {
        ...event,
        key: "Enter",
        preventDefault: vi.fn(),
      } as unknown as React.KeyboardEvent<HTMLElement>;

      // Act
      act(() => {
        result.current.handleKeyDown(reactEvent);
      });

      // Assert
      expect(mockCopyToClipboard).not.toHaveBeenCalled();
      expect(reactEvent.preventDefault).not.toHaveBeenCalled();
    });

    /**
     * @description Should call handleCopy and preventDefault when key is Enter and copyable true
     * @scenario copyable = true, event key = "Enter"
     * @expected preventDefault called, copyToClipboardWithFeedback called
     */
    it("should call handleCopy and preventDefault on Enter key", async () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(true, false, "5", 5));
      const event = new KeyboardEvent("keydown", { key: "Enter" });
      const reactEvent = {
        ...event,
        key: "Enter",
        preventDefault: vi.fn(),
      } as unknown as React.KeyboardEvent<HTMLElement>;

      // Act
      act(() => {
        result.current.handleKeyDown(reactEvent);
      });

      // Assert
      expect(reactEvent.preventDefault).toHaveBeenCalled();
      expect(mockCopyToClipboard).toHaveBeenCalled();
    });

    /**
     * @description Should call handleCopy and preventDefault when key is Space and copyable true
     * @scenario copyable = true, event key = " "
     * @expected preventDefault called, copyToClipboardWithFeedback called
     */
    it("should call handleCopy and preventDefault on Space key", async () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(true, false, "5", 5));
      const event = new KeyboardEvent("keydown", { key: " " });
      const reactEvent = {
        ...event,
        key: " ",
        preventDefault: vi.fn(),
      } as unknown as React.KeyboardEvent<HTMLElement>;

      // Act
      act(() => {
        result.current.handleKeyDown(reactEvent);
      });

      // Assert
      expect(reactEvent.preventDefault).toHaveBeenCalled();
      expect(mockCopyToClipboard).toHaveBeenCalled();
    });

    /**
     * @description Should not do anything when key is not Enter or Space (even if copyable true)
     * @scenario copyable = true, event key = "Tab"
     * @expected preventDefault not called, copy not triggered
     */
    it("should not copy on other keys", () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(true, false, "5", 5));
      const event = new KeyboardEvent("keydown", { key: "Tab" });
      const reactEvent = {
        ...event,
        key: "Tab",
        preventDefault: vi.fn(),
      } as unknown as React.KeyboardEvent<HTMLElement>;

      // Act
      act(() => {
        result.current.handleKeyDown(reactEvent);
      });

      // Assert
      expect(reactEvent.preventDefault).not.toHaveBeenCalled();
      expect(mockCopyToClipboard).not.toHaveBeenCalled();
    });
  });

  describe("combinedClickHandler", () => {
    /**
     * @description Should call handleCopy and externalOnClick when provided
     * @scenario copyable = true, externalOnClick provided, click event
     * @expected handleCopy triggers copy, externalOnClick called with event
     */
    it("should call handleCopy and externalOnClick", async () => {
      // Arrange
      const externalOnClick = vi.fn();
      const { result } = renderHook(() =>
        useBadgeCopy(true, false, "5", 5, externalOnClick),
      );
      const mockEvent = {} as React.MouseEvent<HTMLElement>;

      // Act
      await act(async () => {
        result.current.combinedClickHandler(mockEvent);
      });

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalled();
      expect(externalOnClick).toHaveBeenCalledWith(mockEvent);
    });

    /**
     * @description Should call handleCopy but not externalOnClick when externalOnClick is undefined
     * @scenario copyable = true, externalOnClick = undefined
     * @expected handleCopy called, no error
     */
    it("should call handleCopy without externalOnClick when not provided", async () => {
      // Arrange
      const { result } = renderHook(() => useBadgeCopy(true, false, "5", 5));
      const mockEvent = {} as React.MouseEvent<HTMLElement>;

      // Act
      await act(async () => {
        result.current.combinedClickHandler(mockEvent);
      });

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalled();
    });

    /**
     * @description Should not copy when copyable is false, but still call externalOnClick
     * @scenario copyable = false, externalOnClick provided
     * @expected copy not triggered, externalOnClick called
     */
    it("should not copy when copyable false but still call externalOnClick", async () => {
      // Arrange
      const externalOnClick = vi.fn();
      const { result } = renderHook(() =>
        useBadgeCopy(false, false, "5", 5, externalOnClick),
      );
      const mockEvent = {} as React.MouseEvent<HTMLElement>;

      // Act
      await act(async () => {
        result.current.combinedClickHandler(mockEvent);
      });

      // Assert
      expect(mockCopyToClipboard).not.toHaveBeenCalled();
      expect(externalOnClick).toHaveBeenCalledWith(mockEvent);
    });
  });
});