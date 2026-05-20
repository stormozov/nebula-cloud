import { act, renderHook } from "@testing-library/react";
import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import {
  cancelUpload,
  clearCompleted,
  type IUploadFile as IUploadFileEntity,
  removeFile,
  retryUpload,
  selectCanClosePanel,
  selectIsPanelVisible,
  selectIsQueueCompleted,
  selectUploadQueue,
  selectUploadStats,
  setPanelVisible,
} from "@/entities/file-upload";
import { useAnimatedClose } from "@/shared/hooks";

import { useFileUploadPanel } from "../useFileUploadPanel";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/app/store/hooks", () => {
  return {
    useAppDispatch: vi.fn(),
    useAppSelector: vi.fn(),
  };
});

vi.mock("@/shared/hooks", () => {
  return {
    useAnimatedClose: vi.fn(),
  };
});

vi.mock("@/entities/file-upload", async () => {
  const selectors = await vi.importActual("@/entities/file-upload");

  return {
    ...selectors,
    // Action creators: we need to validate payloads dispatched.
    setPanelVisible: vi.fn((value: boolean) => ({
      type: "setPanelVisible",
      payload: value,
    })),
    clearCompleted: vi.fn(() => ({ type: "clearCompleted" })),
    cancelUpload: vi.fn((payload: { uploadId: string }) => ({
      type: "cancelUpload",
      payload,
    })),
    retryUpload: vi.fn((payload: { uploadId: string }) => ({
      type: "retryUpload",
      payload,
    })),
    removeFile: vi.fn((payload: { uploadId: string }) => ({
      type: "removeFile",
      payload,
    })),
  };
});

// =============================================================================
// TESTS
// =============================================================================

describe("useFileUploadPanel", () => {
  const mockDispatch = vi.fn();
  const animatedCloseHandle = vi.fn();
  const animatedCloseOnClose = { current: (() => {}) as () => void };

  const mockQueue = [
    {
      id: "u1",
      file: {
        name: "a.txt",
        size: 10,
        type: "text/plain",
        lastModified: 1,
        comment: "",
      },
      progress: 30,
      status: "uploading",
    },
    {
      id: "u2",
      file: {
        name: "b.txt",
        size: 20,
        type: "text/plain",
        lastModified: 2,
        comment: "c",
      },
      progress: 100,
      status: "success",
    },
  ] satisfies IUploadFileEntity[];

  const mockStats = {
    total: 2,
    pending: 0,
    uploading: 1,
    success: 1,
    error: 0,
    totalUploaded: 5,
    totalFailed: 0,
    isCompleted: false,
  };

  beforeEach(() => {
    vi.clearAllMocks();

    (useAppDispatch as unknown as Mock).mockReturnValue(mockDispatch);

    (useAppSelector as unknown as Mock).mockImplementation(
      (selectorFn: (s: unknown) => unknown) => {
        switch (selectorFn) {
          case selectUploadQueue:
            return mockQueue;
          case selectIsPanelVisible:
            return true;
          case selectIsQueueCompleted:
            return false;
          case selectCanClosePanel:
            return false;
          case selectUploadStats:
            return mockStats;
          default:
            return undefined;
        }
      },
    );

    animatedCloseHandle.mockImplementation(() => {
      animatedCloseOnClose.current();
    });

    (useAnimatedClose as unknown as Mock).mockImplementation(
      (props: {
        onClose: () => void;
        isBlocked?: boolean;
        animationDuration?: number;
      }) => {
        animatedCloseOnClose.current = props.onClose;
        return {
          isClosing: false,
          handleCloseWithAnimation: animatedCloseHandle,
        };
      },
    );
  });

  describe("when hook is initialized", () => {
    /**
     * @description Should return queue and panel state derived from selectors
     * @scenario useFileUploadPanel is rendered with selectors mocked
     * @expected returned values match selector outputs and useAnimatedClose return values
     */
    it("should return queue and upload panel state when selectors provide values", () => {
      // Arrange
      // (mocks prepared in beforeEach)

      // Act
      const { result } = renderHook(() => useFileUploadPanel());

      // Assert
      expect(result.current.queue).toEqual(mockQueue);
      expect(result.current.isPanelVisible).toBe(true);
      expect(result.current.isQueueCompleted).toBe(false);
      expect(result.current.stats).toEqual(mockStats);
      expect(result.current.isClosing).toBe(false);
      expect(result.current.canClosePanel).toBe(false);
      expect(typeof result.current.handleCloseWithAnimation).toBe("function");
      expect(typeof result.current.handleCancel).toBe("function");
      expect(typeof result.current.handleRetry).toBe("function");
      expect(typeof result.current.handleRemove).toBe("function");
    });

    /**
     * @description Should pass isBlocked as inverted canClosePanel into useAnimatedClose
     * @scenario canClosePanel selector returns false
     * @expected useAnimatedClose receives isBlocked = true
     */
    it("should set isBlocked to true when canClosePanel is false", () => {
      // Arrange
      const animatedCloseMock = useAnimatedClose as unknown as Mock;

      // Act
      renderHook(() => useFileUploadPanel());

      // Assert
      const call = animatedCloseMock.mock.calls[0];
      expect(call[0]).toMatchObject({
        isBlocked: true,
        animationDuration: 300,
      });
    });
  });

  describe("when user cancels an upload", () => {
    /**
     * @description Should dispatch cancelUpload action with provided uploadId
     * @scenario handleCancel(uploadId) is called
     * @expected dispatch is called with cancelUpload({ uploadId })
     */
    it("should dispatch cancelUpload with uploadId when handleCancel is called", () => {
      // Arrange
      const uploadId = "u1";
      const cancelUploadMock = cancelUpload as unknown as Mock;

      const { result } = renderHook(() => useFileUploadPanel());

      // Act
      act(() => {
        result.current.handleCancel(uploadId);
      });

      // Assert
      expect(cancelUploadMock).toHaveBeenCalledWith({ uploadId });
      expect(mockDispatch).toHaveBeenCalledWith({
        type: "cancelUpload",
        payload: { uploadId },
      });
    });
  });

  describe("when user retries a failed upload", () => {
    /**
     * @description Should dispatch retryUpload action with provided uploadId and warn
     * @scenario handleRetry(uploadId) is called
     * @expected retryUpload dispatched and console.warn called with uploadId
     */
    it("should dispatch retryUpload and warn when handleRetry is called", () => {
      // Arrange
      const uploadId = "u2";
      const retryUploadMock = retryUpload as unknown as Mock;
      const warnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => undefined);

      const { result } = renderHook(() => useFileUploadPanel());

      // Act
      act(() => {
        result.current.handleRetry(uploadId);
      });

      // Assert
      expect(retryUploadMock).toHaveBeenCalledWith({ uploadId });
      expect(mockDispatch).toHaveBeenCalledWith({
        type: "retryUpload",
        payload: { uploadId },
      });
      expect(warnSpy).toHaveBeenCalledWith("Retry upload:", uploadId);
    });
  });

  describe("when user removes a file from the queue", () => {
    /**
     * @description Should dispatch removeFile action with provided uploadId
     * @scenario handleRemove(uploadId) is called
     * @expected dispatch is called with removeFile({ uploadId })
     */
    it("should dispatch removeFile with uploadId when handleRemove is called", () => {
      // Arrange
      const uploadId = "u1";
      const removeFileMock = removeFile as unknown as Mock;

      const { result } = renderHook(() => useFileUploadPanel());

      // Act
      act(() => {
        result.current.handleRemove(uploadId);
      });

      // Assert
      expect(removeFileMock).toHaveBeenCalledWith({ uploadId });
      expect(mockDispatch).toHaveBeenCalledWith({
        type: "removeFile",
        payload: { uploadId },
      });
    });
  });

  describe("when panel close animation completes", () => {
    /**
     * @description Should dispatch setPanelVisible(false) and clearCompleted on close
     * @scenario handleCloseWithAnimation is invoked and triggers onClose callback
     * @expected both dispatches are performed
     */
    it("should dispatch setPanelVisible false and clearCompleted after close animation", () => {
      // Arrange
      const setPanelVisibleMock = setPanelVisible as unknown as Mock;
      const clearCompletedMock = clearCompleted as unknown as Mock;

      const { result } = renderHook(() => useFileUploadPanel());

      // Act
      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Assert
      expect(setPanelVisibleMock).toHaveBeenCalledWith(false);
      expect(clearCompletedMock).toHaveBeenCalled();
      expect(mockDispatch).toHaveBeenCalledWith({
        type: "setPanelVisible",
        payload: false,
      });
      expect(mockDispatch).toHaveBeenCalledWith({ type: "clearCompleted" });
    });

    /**
     * @description Should set isBlocked to false when canClosePanel is true
     * @scenario canClosePanel selector returns true
     * @expected useAnimatedClose receives isBlocked = false
     */
    it("should set isBlocked to false when canClosePanel is true", () => {
      // Arrange
      (useAppSelector as unknown as Mock).mockImplementation(
        (selectorFn: (s: unknown) => unknown) => {
          switch (selectorFn) {
            case selectUploadQueue:
              return mockQueue;
            case selectIsPanelVisible:
              return true;
            case selectIsQueueCompleted:
              return false;
            case selectCanClosePanel:
              return true;
            case selectUploadStats:
              return mockStats;
            default:
              return undefined;
          }
        },
      );

      const animatedCloseMock = useAnimatedClose as unknown as Mock;

      // Act
      renderHook(() => useFileUploadPanel());

      // Assert
      const call = animatedCloseMock.mock.calls[0];
      expect(call[0]).toMatchObject({
        isBlocked: false,
        animationDuration: 300,
      });
    });
  });
});
