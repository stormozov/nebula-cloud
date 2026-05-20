import { renderHook } from "@testing-library/react";
import type { RefObject } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useClickOutside } from "../useClickOutside";

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Helper to create a MouseEvent with a specified target.
 * @param target - The element to set as event target.
 * @returns A mousedown MouseEvent with the given target.
 */
function createOutsideClickEvent(target: EventTarget): MouseEvent {
  const event = new MouseEvent("mousedown", { bubbles: true });
  Object.defineProperty(event, "target", { value: target, writable: false });
  return event;
}

const renderHookAny = renderHook as unknown as typeof renderHook;

// =============================================================================
// TESTS
// =============================================================================

describe("useClickOutside", () => {
  // Shared variables
  let ref: RefObject<HTMLDivElement | null>;
  let callback: ReturnType<typeof vi.fn<() => void>>;
  let addEventListenerSpy: ReturnType<typeof vi.spyOn>;
  let removeEventListenerSpy: ReturnType<typeof vi.spyOn>;
  let registeredHandler: ((e: MouseEvent) => void) | null;

  beforeEach(() => {
    callback = vi.fn<() => void>();
    ref = { current: null };
    registeredHandler = null;

    addEventListenerSpy = vi
      .spyOn(document, "addEventListener")
      .mockImplementation((type, handler) => {
        if (type === "mousedown") {
          registeredHandler = handler as (e: MouseEvent) => void;
        }
      });
    removeEventListenerSpy = vi.spyOn(document, "removeEventListener");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the hook is mounted", () => {
    it("should add mousedown event listener to document", () => {
      renderHook(() => useClickOutside(ref, callback));

      expect(addEventListenerSpy).toHaveBeenCalledWith(
        "mousedown",
        expect.any(Function),
      );
    });

    it("should not call the callback immediately", () => {
      renderHook(() => useClickOutside(ref, callback));

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe("when a mousedown event occurs", () => {
    it("should call the callback when click is outside the element", () => {
      const div = document.createElement("div");
      ref.current = div;
      renderHook(() => useClickOutside(ref, callback));

      const event = createOutsideClickEvent(document.body);
      registeredHandler?.(event);

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it("should not call the callback when click is inside the element", () => {
      const div = document.createElement("div");
      const innerSpan = document.createElement("span");
      div.appendChild(innerSpan);
      ref.current = div;
      renderHook(() => useClickOutside(ref, callback));

      const event = createOutsideClickEvent(innerSpan);
      registeredHandler?.(event);

      expect(callback).not.toHaveBeenCalled();
    });

    it("should not call the callback when ref is null", () => {
      ref.current = null;
      renderHook(() => useClickOutside(ref, callback));

      const event = createOutsideClickEvent(document.body);
      registeredHandler?.(event);

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe("when the component unmounts", () => {
    it("should remove the event listener on unmount", () => {
      const { unmount } = renderHook(() => useClickOutside(ref, callback));
      const handlerBeforeUnmount = registeredHandler;

      unmount();

      expect(removeEventListenerSpy).toHaveBeenCalledWith(
        "mousedown",
        handlerBeforeUnmount,
      );
    });
  });

  describe("when the callback reference changes", () => {
    it("should call the updated callback on subsequent outside clicks", () => {
      const firstCallback = vi.fn<() => void>();
      const secondCallback = vi.fn<() => void>();

      const div = document.createElement("div");
      ref.current = div;

      const { rerender } = renderHook(
        ({ cb }: { cb: () => void }) => useClickOutside(ref, cb),
        { initialProps: { cb: firstCallback } },
      ) as unknown as { rerender: (props: { cb: () => void }) => void };

      let event = createOutsideClickEvent(document.body);

      registeredHandler?.(event);

      rerender({ cb: secondCallback } as never);

      event = createOutsideClickEvent(document.body);
      registeredHandler?.(event);

      expect(firstCallback).toHaveBeenCalledTimes(1);
      expect(secondCallback).toHaveBeenCalledTimes(1);
    });

    it("should re-register the event listener when callback changes", () => {
      const firstCallback = vi.fn<() => void>();
      const secondCallback = vi.fn<() => void>();

      const div = document.createElement("div");
      ref.current = div;

      const { rerender } = renderHook(
        ({ cb }: { cb: () => void }) => useClickOutside(ref, cb),
        { initialProps: { cb: firstCallback } },
      ) as unknown as { rerender: (props: { cb: () => void }) => void };

      const firstHandler = registeredHandler;

      addEventListenerSpy.mockClear();
      removeEventListenerSpy.mockClear();

      rerender({ cb: secondCallback });

      expect(removeEventListenerSpy).toHaveBeenCalledWith(
        "mousedown",
        firstHandler,
      );
      expect(addEventListenerSpy).toHaveBeenCalledWith(
        "mousedown",
        expect.any(Function),
      );
      expect(addEventListenerSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe("when the ref object changes", () => {
    it("should use the new ref for outside detection", () => {
      const firstCallback = vi.fn<() => void>();

      const ref1: RefObject<HTMLDivElement | null> = { current: null };
      const div = document.createElement("div");
      const ref2: RefObject<HTMLDivElement | null> = { current: div };

      const { rerender } = renderHookAny(
        ({
          ref,
          cb,
        }: {
          ref: RefObject<HTMLDivElement | null>;
          cb: () => void;
        }) => useClickOutside(ref, cb),
        {
          initialProps: { ref: ref1, cb: firstCallback },
        },
      ) as unknown as {
        rerender: (props: {
          ref: RefObject<HTMLDivElement | null>;
          cb: () => void;
        }) => void;
      };

      let event = createOutsideClickEvent(document.body);
      registeredHandler?.(event);
      expect(firstCallback).not.toHaveBeenCalled();

      rerender({ ref: ref2, cb: firstCallback });

      event = createOutsideClickEvent(document.body);
      registeredHandler?.(event);

      expect(firstCallback).toHaveBeenCalledTimes(1);
    });
  });
});
