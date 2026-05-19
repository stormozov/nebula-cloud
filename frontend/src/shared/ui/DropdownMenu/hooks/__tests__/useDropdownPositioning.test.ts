/* eslint-disable @typescript-eslint/no-explicit-any */
/** biome-ignore-all lint/suspicious/noExplicitAny: <tests> */
import { renderHook, waitFor } from "@testing-library/react";
import type { RefObject } from "react";

type MockDOMRect = Pick<
  DOMRect,
  "top" | "left" | "width" | "height" | "bottom" | "right"
>;

const asDomRect = (rect: MockDOMRect): DOMRect => rect as unknown as DOMRect;

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useDropdownPositioning } from "../useDropdownPositioning";

describe("useDropdownPositioning", () => {
  let mockTriggerRef: RefObject<HTMLElement | null>;
  let mockMenuRef: RefObject<HTMLElement | null>;
  let originalResizeObserver: typeof ResizeObserver;

  beforeEach(() => {
    // Reset window dimensions
    Object.defineProperty(window, "innerWidth", {
      value: 1024,
      writable: true,
    });
    Object.defineProperty(window, "innerHeight", {
      value: 768,
      writable: true,
    });

    // Create real DOM elements to avoid null refs
    mockTriggerRef = { current: document.createElement("div") };
    mockMenuRef = { current: document.createElement("div") };

    // Mock ResizeObserver (type-safe)
    originalResizeObserver = window.ResizeObserver;

    let lastInstance: ResizeObserver | null = null;
    const disconnectSpy = vi.fn();

    class MockResizeObserver implements ResizeObserver {
      private _callback: ResizeObserverCallback;

      constructor(callback: ResizeObserverCallback) {
        this._callback = callback;
        lastInstance = undefined as unknown as ResizeObserver;
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        lastInstance = this;
      }

      observe(): void {
        // noop
      }

      unobserve(): void {
        // noop
      }

      disconnect(): void {
        disconnectSpy();
      }

      get callback(): ResizeObserverCallback {
        return this._callback;
      }

      // not part of ResizeObserver interface; kept for potential future needs
      asAny: any = undefined;
    }

    window.ResizeObserver = MockResizeObserver;

    vi.spyOn(window, "addEventListener");
    vi.spyOn(window, "removeEventListener");

    // Expose spies for assertions in tests
    (window as any).__resizeObserverDisconnectSpy = disconnectSpy;
    (window as any).__lastResizeObserverInstance = lastInstance;
  });

  afterEach(() => {
    window.ResizeObserver = originalResizeObserver;
    delete (window as any).__resizeObserverDisconnectSpy;
    delete (window as any).__lastResizeObserverInstance;
    vi.restoreAllMocks();
  });

  describe("when menu is closed", () => {
    it("should set opacity to 0 when isOpen is false", () => {
      const { result } = renderHook(() =>
        useDropdownPositioning({
          isOpen: false,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
        }),
      );

      expect(result.current.menuStyle).toEqual({ opacity: 0 });
      expect(window.addEventListener).not.toHaveBeenCalled();
    });
  });

  describe("when positioning relative to trigger element", () => {
    const mockTriggerRect: MockDOMRect = {
      top: 100,
      left: 200,
      width: 100,
      height: 40,
      bottom: 140,
      right: 300,
    };

    beforeEach(() => {
      // Mock getBoundingClientRect on the real element
      if (!mockTriggerRef.current)
        throw new Error("mockTriggerRef.current is null");
      mockTriggerRef.current.getBoundingClientRect = () =>
        asDomRect(mockTriggerRect);

      // Set offset dimensions via defineProperty
      if (!mockMenuRef.current) throw new Error("mockMenuRef.current is null");
      Object.defineProperty(mockMenuRef.current, "offsetWidth", {
        value: 150,
        configurable: true,
      });
      Object.defineProperty(mockMenuRef.current, "offsetHeight", {
        value: 200,
        configurable: true,
      });
    });

    it("should use bottom-start placement by default", async () => {
      const { result } = renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
        }),
      );

      await waitFor(() => {
        expect(result.current.menuStyle.opacity).toBe(1);
        expect(result.current.menuStyle).toMatchObject({
          top: 140,
          left: 200,
        });
      });
    });

    it("should position at bottom-end", async () => {
      const { result } = renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
          placement: "bottom-end",
        }),
      );

      await waitFor(() => {
        expect(result.current.menuStyle.opacity).toBe(1);
        expect(result.current.menuStyle).toMatchObject({
          top: 140,
          left: 200 + 100 - 150,
        });
      });
    });

    it("should flip to bottom when top placement overflows viewport", async () => {
      // Trigger near top of viewport
      const topTriggerRect = { ...mockTriggerRect, top: 50, bottom: 90 };

      if (!mockTriggerRef.current)
        throw new Error("mockTriggerRef.current is null");
      mockTriggerRef.current.getBoundingClientRect = () =>
        asDomRect(topTriggerRect);

      if (!mockMenuRef.current) throw new Error("mockMenuRef.current is null");

      Object.defineProperty(mockMenuRef.current, "offsetHeight", {
        value: 200,
        configurable: true,
      });

      const { result } = renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
          placement: "top-start",
        }),
      );

      await waitFor(() => {
        expect(result.current.menuStyle.opacity).toBe(1);
        expect(result.current.menuStyle).toMatchObject({
          top: 90,
          left: 200,
        });
      });
    });

    it("should clamp vertical position to viewport edges", async () => {
      Object.defineProperty(window, "innerHeight", {
        value: 100,
        writable: true,
      });

      if (!mockMenuRef.current) throw new Error("mockMenuRef.current is null");
      Object.defineProperty(mockMenuRef.current, "offsetHeight", {
        value: 200,
        configurable: true,
      });

      const triggerRect = { ...mockTriggerRect, top: 80 };
      if (!mockTriggerRef.current)
        throw new Error("mockTriggerRef.current is null");
      mockTriggerRef.current.getBoundingClientRect = () =>
        asDomRect(triggerRect);

      const { result } = renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
          placement: "bottom-start",
        }),
      );

      await waitFor(() => {
        expect(result.current.menuStyle.opacity).toBe(1);
        expect(result.current.menuStyle.top).toBe(8);
      });
    });
  });

  describe("event listeners and cleanup", () => {
    it("should add resize and scroll listeners when position is not provided", async () => {
      if (!mockMenuRef.current) throw new Error("mockMenuRef.current is null");

      Object.defineProperty(mockMenuRef.current, "offsetWidth", {
        value: 100,
        configurable: true,
      });
      Object.defineProperty(mockMenuRef.current, "offsetHeight", {
        value: 100,
        configurable: true,
      });

      renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
        }),
      );

      await waitFor(() => {
        expect(window.addEventListener).toHaveBeenCalledWith(
          "resize",
          expect.any(Function),
        );
        expect(window.addEventListener).toHaveBeenCalledWith(
          "scroll",
          expect.any(Function),
        );
      });
    });

    it("should remove event listeners on cleanup", async () => {
      if (!mockMenuRef.current) throw new Error("mockMenuRef.current is null");

      Object.defineProperty(mockMenuRef.current, "offsetWidth", {
        value: 100,
        configurable: true,
      });
      Object.defineProperty(mockMenuRef.current, "offsetHeight", {
        value: 100,
        configurable: true,
      });

      const { unmount } = renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
        }),
      );

      await waitFor(() => {
        expect(window.addEventListener).toHaveBeenCalled();
      });

      unmount();

      // Note: since handlers are created inside hook, we assert by call patterns
      expect(window.removeEventListener).toHaveBeenCalledWith(
        "resize",
        expect.any(Function),
      );
      expect(window.removeEventListener).toHaveBeenCalledWith(
        "scroll",
        expect.any(Function),
      );
    });

    it("should cancel animation frame and disconnect ResizeObserver on cleanup", async () => {
      const cancelSpy = vi.spyOn(window, "cancelAnimationFrame");

      if (!mockMenuRef.current) throw new Error("mockMenuRef.current is null");
      Object.defineProperty(mockMenuRef.current, "offsetWidth", {
        value: 0,
        configurable: true,
      });
      Object.defineProperty(mockMenuRef.current, "offsetHeight", {
        value: 0,
        configurable: true,
      });

      const disconnectSpy = (window as any).__resizeObserverDisconnectSpy as
        | ReturnType<typeof vi.fn>
        | undefined;

      const { unmount } = renderHook(() =>
        useDropdownPositioning({
          isOpen: true,
          triggerRef: mockTriggerRef,
          menuRef: mockMenuRef,
        }),
      );

      await new Promise((resolve) => setTimeout(resolve, 10));
      unmount();

      expect(cancelSpy).toHaveBeenCalled();
      expect(disconnectSpy).toBeDefined();
      expect(disconnectSpy).toHaveBeenCalled();
    });
  });
});
