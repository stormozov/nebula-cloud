import { act, renderHook } from "@testing-library/react";
import type React from "react";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { getAdjustedAnchorPositionTransform } from "@/shared/utils";

import { useViewportBoundary } from "../useViewportBoundary";

vi.mock("@/shared/utils", () => ({
  getAdjustedAnchorPositionTransform: vi.fn(),
}));

describe("useViewportBoundary", () => {
  let mockGetAdjustedTransform: ReturnType<typeof vi.fn>;
  let originalRequestAnimationFrame: typeof requestAnimationFrame;
  let originalResizeObserver: typeof ResizeObserver;

  beforeAll(() => {
    originalResizeObserver = window.ResizeObserver;
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockGetAdjustedTransform = getAdjustedAnchorPositionTransform as ReturnType<
      typeof vi.fn
    >;
    mockGetAdjustedTransform.mockReturnValue("translate(0px, 0px)");

    originalRequestAnimationFrame = window.requestAnimationFrame;
    window.requestAnimationFrame = vi.fn((cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });

    // Добавляем шпионы для addEventListener и removeEventListener
    vi.spyOn(window, "addEventListener");
    vi.spyOn(window, "removeEventListener");
  });

  afterEach(() => {
    window.requestAnimationFrame = originalRequestAnimationFrame;
    window.ResizeObserver = originalResizeObserver;
    vi.restoreAllMocks();
  });

  describe("when position is not provided", () => {
    /**
     * @description Should set transform to empty string and isPositionReady to true
     * @scenario position = undefined
     * @expected transform = "", isPositionReady = true
     */
    it("should return empty transform and isPositionReady true", () => {
      // Arrange
      const elementRef = { current: document.createElement("div") };

      // Act
      const { result } = renderHook(() =>
        useViewportBoundary(elementRef, undefined),
      );

      // Assert
      expect(result.current.transform).toBe("");
      expect(result.current.isPositionReady).toBe(true);
    });

    /**
     * @description Should not set up any observers or event listeners when position undefined
     * @scenario position = undefined
     * @expected ResizeObserver not created, no resize listener added
     */
    it("should not set up ResizeObserver or resize listener", () => {
      // Arrange
      const elementRef = { current: document.createElement("div") };
      const resizeObserverSpy = vi.fn().mockImplementation(() => ({
        observe: vi.fn(),
        disconnect: vi.fn(),
      }));
      window.ResizeObserver =
        resizeObserverSpy as unknown as typeof ResizeObserver;

      // Act
      renderHook(() => useViewportBoundary(elementRef, undefined));

      // Assert
      expect(resizeObserverSpy).not.toHaveBeenCalled();
      expect(window.addEventListener).not.toHaveBeenCalledWith(
        "resize",
        expect.any(Function),
      );
    });
  });

  describe("when position is provided but elementRef.current is null", () => {
    /**
     * @description Should return initial state (transform "" and isPositionReady false) and not calculate transform
     * @scenario position = 'top-right', elementRef.current = null
     * @expected transform = "", isPositionReady = false, getAdjustedTransform not called
     */
    it("should not calculate transform when elementRef is null", () => {
      // Arrange
      const elementRef = { current: null };
      window.ResizeObserver = vi.fn() as unknown as typeof ResizeObserver;

      // Act
      const { result } = renderHook(() =>
        useViewportBoundary(elementRef, "top-right"),
      );

      // Assert
      expect(result.current.transform).toBe("");
      expect(result.current.isPositionReady).toBe(false);
      expect(mockGetAdjustedTransform).not.toHaveBeenCalled();
    });
  });

  describe("when position is provided and elementRef exists", () => {
    let element: HTMLElement;
    let elementRef: React.RefObject<HTMLElement>;

    beforeEach(() => {
      element = document.createElement("div");
      element.getBoundingClientRect = vi.fn().mockReturnValue({
        top: 100,
        left: 100,
        width: 50,
        height: 50,
        right: 150,
        bottom: 150,
      });
      elementRef = { current: element };

      // Мокаем ResizeObserver как класс, который можно инстанцировать
      window.ResizeObserver = class MockResizeObserver {
        observe = vi.fn();
        disconnect = vi.fn();
      } as unknown as typeof ResizeObserver;
    });

    /**
     * @description Should calculate transform using getAdjustedAnchorPositionTransform
     * @scenario position = 'top-right', element exists
     * @expected getAdjustedTransform called with correct parameters, transform set, isPositionReady remains false
     */
    it("should calculate transform on mount", () => {
      // Arrange
      mockGetAdjustedTransform.mockReturnValue(
        "translate(calc(-50% + 5px), calc(-50% + 3px))",
      );

      // Act
      const { result } = renderHook(() =>
        useViewportBoundary(elementRef, "top-right"),
      );

      // Assert
      expect(mockGetAdjustedTransform).toHaveBeenCalledWith({
        position: "top-right",
        elementRect: element.getBoundingClientRect(),
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
        padding: 4,
      });
      expect(result.current.transform).toBe(
        "translate(calc(-50% + 5px), calc(-50% + 3px))",
      );
      expect(result.current.isPositionReady).toBe(false);
    });

    /**
     * @description Should set up ResizeObserver and observe element
     * @scenario position provided, element exists
     * @expected ResizeObserver created and observe called with element
     */
    it("should set up ResizeObserver and observe element", () => {
      // Arrange
      const observeSpy = vi.fn();
      window.ResizeObserver = class {
        observe = observeSpy;
        disconnect = vi.fn();
      } as unknown as typeof ResizeObserver;

      // Act
      renderHook(() => useViewportBoundary(elementRef, "bottom-left"));

      // Assert
      expect(observeSpy).toHaveBeenCalledWith(element);
    });

    /**
     * @description Should call resize observer callback on ResizeObserver trigger
     * @scenario ResizeObserver triggers, calculateTransform called again
     * @expected getAdjustedTransform called additional time
     */
    it("should recalculate transform on ResizeObserver callback", () => {
      // Arrange
      let capturedCallback: ResizeObserverCallback | undefined;
      window.ResizeObserver = class {
        observe = vi.fn();
        disconnect = vi.fn();
        constructor(callback: ResizeObserverCallback) {
          capturedCallback = callback;
        }
      } as unknown as typeof ResizeObserver;
      mockGetAdjustedTransform.mockReturnValue("initial");
      renderHook(() => useViewportBoundary(elementRef, "top-right"));

      // Act
      act(() => {
        if (capturedCallback) {
          capturedCallback([], {} as ResizeObserver);
        }
      });

      // Assert
      expect(mockGetAdjustedTransform).toHaveBeenCalledTimes(2);
    });

    /**
     * @description Should add resize event listener on window
     * @scenario position provided, element exists
     * @expected window.addEventListener called with 'resize'
     */
    it("should add resize event listener", () => {
      // Act
      renderHook(() => useViewportBoundary(elementRef, "top-right"));

      // Assert
      expect(window.addEventListener).toHaveBeenCalledWith(
        "resize",
        expect.any(Function),
      );
    });

    /**
     * @description Should recalculate transform on window resize
     * @scenario window resize event triggers
     * @expected getAdjustedTransform called again
     */
    it("should recalculate transform on window resize", () => {
      // Arrange
      let resizeHandler: (() => void) | undefined;
      // На время этого теста временно переопределяем реализацию шпиона, чтобы захватить обработчик
      const addEventListenerMock =
        window.addEventListener as unknown as ReturnType<typeof vi.fn>;
      addEventListenerMock.mockImplementation((event, handler) => {
        if (event === "resize") resizeHandler = handler as () => void;
      });
      mockGetAdjustedTransform.mockReturnValue("initial");
      renderHook(() => useViewportBoundary(elementRef, "top-right"));

      // Act
      act(() => {
        if (resizeHandler) resizeHandler();
      });

      // Assert
      expect(mockGetAdjustedTransform).toHaveBeenCalledTimes(2);
    });

    /**
     * @description Should clean up ResizeObserver and remove resize listener on unmount
     * @scenario component unmounts
     * @expected observer.disconnect called, removeEventListener called
     */
    it("should clean up ResizeObserver and remove resize listener on unmount", () => {
      // Arrange
      const disconnectSpy = vi.fn();
      window.ResizeObserver = class {
        observe = vi.fn();
        disconnect = disconnectSpy;
      } as unknown as typeof ResizeObserver;
      const { unmount } = renderHook(() =>
        useViewportBoundary(elementRef, "top-right"),
      );

      // Act
      unmount();

      // Assert
      expect(disconnectSpy).toHaveBeenCalled();
      expect(window.removeEventListener).toHaveBeenCalledWith(
        "resize",
        expect.any(Function),
      );
    });
  });
});
