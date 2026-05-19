import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useModalConfirm } from "../useModalConfirm";

describe("useModalConfirm", () => {
  describe("initial state", () => {
    /**
     * @description Should initialize with default dialog state
     * @scenario Hook is called without any arguments
     * @expected isOpen is false, title and message are empty strings, onConfirm is async empty function
     */
    it("should return dialog with isOpen false, empty title and message", () => {
      // Arrange & Act
      const { result } = renderHook(() => useModalConfirm());

      // Assert
      expect(result.current.dialog).toEqual({
        isOpen: false,
        title: "",
        message: "",
        onConfirm: expect.any(Function),
      });
    });
  });

  describe("requestConfirm", () => {
    /**
     * @description Should open modal with provided title, message and onConfirm callback
     * @scenario Call requestConfirm with specific title, message and async callback
     * @expected dialog.isOpen becomes true, dialog fields match provided values
     */
    it("should set dialog to open with correct title, message and onConfirm", () => {
      // Arrange
      const { result } = renderHook(() => useModalConfirm());
      const mockOnConfirm = vi.fn(async () => {});

      // Act
      act(() => {
        result.current.requestConfirm(
          "Delete Item",
          "Are you sure?",
          mockOnConfirm,
        );
      });

      // Assert
      expect(result.current.dialog).toEqual({
        isOpen: true,
        title: "Delete Item",
        message: "Are you sure?",
        onConfirm: mockOnConfirm,
      });
    });
  });

  describe("handleConfirm", () => {
    /**
     * @description Should call provided onConfirm callback and then close modal
     * @scenario Modal is open with async onConfirm, then handleConfirm is called
     * @expected onConfirm is called once, dialog.isOpen becomes false
     */
    it("should call onConfirm and close modal when handleConfirm is invoked", async () => {
      // Arrange
      const { result } = renderHook(() => useModalConfirm());
      const mockOnConfirm = vi.fn(async () => {});

      act(() => {
        result.current.requestConfirm("Title", "Message", mockOnConfirm);
      });
      expect(result.current.dialog.isOpen).toBe(true);

      // Act
      await act(async () => {
        await result.current.handleConfirm();
      });

      // Assert
      expect(mockOnConfirm).toHaveBeenCalledTimes(1);
      expect(result.current.dialog.isOpen).toBe(false);
    });

    /**
     * @description Should keep modal open and propagate error when onConfirm throws
     * @scenario onConfirm callback rejects with error, handleConfirm is called
     * @expected Modal remains open, error is thrown, onConfirm called once
     */
    it("should keep modal open and propagate error when onConfirm throws", async () => {
      // Arrange
      const { result } = renderHook(() => useModalConfirm());
      const mockError = new Error("Network failure");
      const mockOnConfirm = vi.fn(async () => {
        throw mockError;
      });

      act(() => {
        result.current.requestConfirm("Title", "Message", mockOnConfirm);
      });
      expect(result.current.dialog.isOpen).toBe(true);

      // Act & Assert
      await act(async () => {
        await expect(result.current.handleConfirm()).rejects.toThrow(mockError);
      });
      // Modal stays open because error interrupted the close logic
      expect(result.current.dialog.isOpen).toBe(true);
      expect(mockOnConfirm).toHaveBeenCalledTimes(1);
    });
  });

  describe("handleCancel", () => {
    /**
     * @description Should close modal without calling onConfirm
     * @scenario Modal is open, handleCancel is called
     * @expected dialog.isOpen becomes false, onConfirm not called
     */
    it("should close modal without calling onConfirm", () => {
      // Arrange
      const { result } = renderHook(() => useModalConfirm());
      const mockOnConfirm = vi.fn(async () => {});

      act(() => {
        result.current.requestConfirm("Title", "Message", mockOnConfirm);
      });
      expect(result.current.dialog.isOpen).toBe(true);

      // Act
      act(() => {
        result.current.handleCancel();
      });

      // Assert
      expect(result.current.dialog.isOpen).toBe(false);
      expect(mockOnConfirm).not.toHaveBeenCalled();
    });
  });

  describe("multiple sequential actions", () => {
    /**
     * @description Should allow opening modal again after confirmation
     * @scenario Open modal, confirm (close), then open again with different params
     * @expected Second open works correctly with new values
     */
    it("should allow reopening modal after handleConfirm", async () => {
      // Arrange
      const { result } = renderHook(() => useModalConfirm());
      const onConfirm1 = vi.fn(async () => {});
      const onConfirm2 = vi.fn(async () => {});

      // Act - first open and confirm
      act(() => {
        result.current.requestConfirm("First", "Message 1", onConfirm1);
      });
      expect(result.current.dialog.isOpen).toBe(true);

      await act(async () => {
        await result.current.handleConfirm();
      });
      expect(result.current.dialog.isOpen).toBe(false);
      expect(onConfirm1).toHaveBeenCalledTimes(1);

      // Act - second open
      act(() => {
        result.current.requestConfirm("Second", "Message 2", onConfirm2);
      });

      // Assert
      expect(result.current.dialog).toEqual({
        isOpen: true,
        title: "Second",
        message: "Message 2",
        onConfirm: onConfirm2,
      });
    });

    /**
     * @description Should allow cancel and then open again
     * @scenario Open modal, cancel, then open again
     * @expected Second open works correctly
     */
    it("should allow reopening modal after handleCancel", () => {
      // Arrange
      const { result } = renderHook(() => useModalConfirm());
      const onConfirm1 = vi.fn(async () => {});
      const onConfirm2 = vi.fn(async () => {});

      // Act - first open and cancel
      act(() => {
        result.current.requestConfirm("First", "Message 1", onConfirm1);
      });
      expect(result.current.dialog.isOpen).toBe(true);

      act(() => {
        result.current.handleCancel();
      });
      expect(result.current.dialog.isOpen).toBe(false);

      // Act - second open
      act(() => {
        result.current.requestConfirm("Second", "Message 2", onConfirm2);
      });

      // Assert
      expect(result.current.dialog).toEqual({
        isOpen: true,
        title: "Second",
        message: "Message 2",
        onConfirm: onConfirm2,
      });
    });
  });
});
