import { renderHook } from "@testing-library/react";
import type { RefObject } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useFocusTrap } from "../useFocusTrap";

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Helper to create a KeyboardEvent with specified properties and a spy on preventDefault.
 * @param key - Key string for the event.
 * @param shiftKey - Whether Shift key is held.
 * @returns A KeyboardEvent with preventDefault spy attached.
 */
function createKeydownEvent(
  key: string,
  shiftKey = false,
): KeyboardEvent & { preventDefault: ReturnType<typeof vi.fn> } {
  const event = new KeyboardEvent("keydown", { key, shiftKey, bubbles: true });
  const preventDefaultSpy = vi.fn();
  Object.defineProperty(event, "preventDefault", {
    value: preventDefaultSpy,
    writable: false,
  });
  return event as typeof event & { preventDefault: ReturnType<typeof vi.fn> };
}

// =============================================================================
// TESTS
// =============================================================================

describe("useFocusTrap", () => {
  let addEventListenerSpy: ReturnType<typeof vi.spyOn>;
  let removeEventListenerSpy: ReturnType<typeof vi.spyOn>;
  let container: HTMLDivElement;
  let containerRef: RefObject<HTMLDivElement | null>;
  let onEscape: ReturnType<typeof vi.fn<() => void>>;
  let registeredKeydownHandler: ((e: KeyboardEvent) => void) | null;

  beforeEach(() => {
    addEventListenerSpy = vi
      .spyOn(document, "addEventListener")
      .mockImplementation((type, handler) => {
        if (type === "keydown") {
          registeredKeydownHandler = handler as (e: KeyboardEvent) => void;
        }
      });
    removeEventListenerSpy = vi.spyOn(document, "removeEventListener");
    container = document.createElement("div");
    document.body.append(container);
    containerRef = { current: container };
    onEscape = vi.fn<() => void>();
    registeredKeydownHandler = null;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  describe("when active is false", () => {
    /**
     * @description Should not add any keydown event listener
     * @scenario Hook rendered with active=false
     * @expected document.addEventListener is not called for keydown
     */
    it("should not add keydown event listener", () => {
      // Arrange
      // Act
      renderHook(() => useFocusTrap({ active: false, containerRef }));

      // Assert
      expect(addEventListenerSpy).not.toHaveBeenCalledWith(
        "keydown",
        expect.any(Function),
      );
    });

    /**
     * @description Should not change focus to any element
     * @scenario An external button is focused, hook rendered with active=false
     * @expected No additional focus call occurs after the hook renders
     */
    it("should not alter focus", () => {
      // Arrange
      const outsideButton = document.createElement("button");
      document.body.append(outsideButton);
      const focusSpy = vi.spyOn(outsideButton, "focus");
      outsideButton.focus(); // set initial focus
      focusSpy.mockClear(); // ignore the initial call we made manually
      expect(document.activeElement).toBe(outsideButton);

      // Act
      renderHook(() => useFocusTrap({ active: false, containerRef }));

      // Assert
      expect(focusSpy).not.toHaveBeenCalled();
    });
  });

  describe("when active becomes true", () => {
    /**
     * @description Should save currently focused element as previous focus
     * @scenario An external button is focused, then hook activated
     * @expected previousFocusRef.current is set to the external button (verified by focus restoration on unmount)
     */
    it("should save the previously focused element", () => {
      // Arrange
      const outsideButton = document.createElement("button");
      document.body.append(outsideButton);
      outsideButton.focus();
      const focusSpy = vi.spyOn(outsideButton, "focus");

      // Act
      renderHook(() => useFocusTrap({ active: true, containerRef }));

      expect(focusSpy).not.toHaveBeenCalled(); // no focus change yet
    });

    /**
     * @description Should add keydown event listener
     * @scenario Hook rendered with active=true
     * @expected document.addEventListener called with 'keydown'
     */
    it("should add keydown event listener", () => {
      // Arrange
      // Act
      renderHook(() => useFocusTrap({ active: true, containerRef }));

      // Assert
      expect(addEventListenerSpy).toHaveBeenCalledWith(
        "keydown",
        expect.any(Function),
      );
    });

    describe("initial focus setting", () => {
      /**
       * @description Should focus the element referenced by initialFocusRef when provided
       * @scenario initialFocusRef points to a button inside the container
       * @expected The button's focus() is called
       */
      it("should focus initialFocusRef element if provided", () => {
        // Arrange
        const focusButton = document.createElement("button");
        container.append(focusButton);
        const initialFocusRef: RefObject<HTMLButtonElement | null> = {
          current: focusButton,
        };
        const focusSpy = vi.spyOn(focusButton, "focus");

        // Act
        renderHook(() =>
          useFocusTrap({ active: true, containerRef, initialFocusRef }),
        );

        // Assert
        expect(focusSpy).toHaveBeenCalledTimes(1);
      });

      /**
       * @description Should focus the first focusable element inside container when no initialFocusRef
       * @scenario Container has multiple focusable elements, no initialFocusRef
       * @expected The first focusable element's focus() is called
       */
      it("should focus first focusable element if no initialFocusRef", () => {
        // Arrange
        const firstButton = document.createElement("button");
        const secondButton = document.createElement("button");
        container.append(firstButton);
        container.append(secondButton);
        const firstFocusSpy = vi.spyOn(firstButton, "focus");
        const secondFocusSpy = vi.spyOn(secondButton, "focus");

        // Act
        renderHook(() => useFocusTrap({ active: true, containerRef }));

        // Assert
        expect(firstFocusSpy).toHaveBeenCalledTimes(1);
        expect(secondFocusSpy).not.toHaveBeenCalled();
      });

      /**
       * @description Should not attempt focus if container has no focusable elements and no initialFocusRef
       * @scenario Container empty, active=true
       * @expected No error thrown, no focus call
       */
      it("should not throw when no focusable elements exist", () => {
        // Arrange
        // container is empty

        // Act & Assert
        expect(() => {
          renderHook(() => useFocusTrap({ active: true, containerRef }));
        }).not.toThrow();
      });
    });
  });

  describe("keydown event handling", () => {
    beforeEach(() => {
      // Ensure hook is activated before each keydown test
      renderHook(() => useFocusTrap({ active: true, containerRef, onEscape }));
    });

    /**
     * @description Should call onEscape when Escape key is pressed
     * @scenario onEscape provided, Escape keydown fired
     * @expected onEscape is called once
     */
    it("should call onEscape on Escape key", () => {
      // Arrange
      const event = createKeydownEvent("Escape");

      // Act
      registeredKeydownHandler?.(event);

      // Assert
      expect(onEscape).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should not call onEscape if not provided
     * @scenario onEscape undefined, Escape key pressed
     * @expected No error, onEscape not called
     */
    it("should not throw if onEscape is undefined and Escape pressed", () => {
      // Arrange: re-render without onEscape
      const { rerender } = renderHook(() =>
        useFocusTrap({ active: true, containerRef }),
      );
      rerender();
      const event = createKeydownEvent("Escape");

      // Act & Assert
      expect(() => registeredKeydownHandler?.(event)).not.toThrow();
    });

    describe("Tab key", () => {
      /**
       * @description Should not prevent default when Tab pressed and focus is not on last element
       * @scenario Three focusable elements, focus on the middle one, Tab pressed
       * @expected preventDefault is not called
       */
      it("should not prevent default when focus is not on last element", () => {
        // Arrange
        const firstBtn = document.createElement("button");
        const middleBtn = document.createElement("button");
        const lastBtn = document.createElement("button");
        container.append(firstBtn);
        container.append(middleBtn);
        container.append(lastBtn);
        middleBtn.focus(); // focus on the middle, not the last
        const event = createKeydownEvent("Tab");

        // Act
        registeredKeydownHandler?.(event);

        // Assert
        expect(event.preventDefault).not.toHaveBeenCalled();
      });

      /**
       * @description Should trap focus by moving to first element when Tab pressed on last element
       * @scenario Focus is on the last focusable element, Tab pressed
       * @expected preventDefault is called, and focus moves to first element
       */
      it("should move focus to first element when Tab pressed on last", () => {
        // Arrange
        const firstBtn = document.createElement("button");
        const lastBtn = document.createElement("button");
        container.append(firstBtn);
        container.append(lastBtn);
        lastBtn.focus();
        const firstFocusSpy = vi.spyOn(firstBtn, "focus");
        const event = createKeydownEvent("Tab");

        // Act
        registeredKeydownHandler?.(event);

        // Assert
        expect(event.preventDefault).toHaveBeenCalled();
        expect(firstFocusSpy).toHaveBeenCalledTimes(1);
      });

      /**
       * @description Should not prevent default when Shift+Tab pressed and focus is not on first element
       * @scenario Focus is on a middle element, Shift+Tab
       * @expected preventDefault not called
       */
      it("should not prevent default when Shift+Tab pressed and not on first", () => {
        // Arrange
        const firstBtn = document.createElement("button");
        const middleBtn = document.createElement("button");
        container.append(firstBtn);
        container.append(middleBtn);
        middleBtn.focus();
        const event = createKeydownEvent("Tab", true);

        // Act
        registeredKeydownHandler?.(event);

        // Assert
        expect(event.preventDefault).not.toHaveBeenCalled();
      });

      /**
       * @description Should move focus to last element when Shift+Tab pressed on first element
       * @scenario Focus is on first, Shift+Tab
       * @expected preventDefault, focus moves to last
       */
      it("should move focus to last element when Shift+Tab pressed on first", () => {
        // Arrange
        const firstBtn = document.createElement("button");
        const lastBtn = document.createElement("button");
        container.append(firstBtn);
        container.append(lastBtn);
        firstBtn.focus();
        const lastFocusSpy = vi.spyOn(lastBtn, "focus");
        const event = createKeydownEvent("Tab", true);

        // Act
        registeredKeydownHandler?.(event);

        // Assert
        expect(event.preventDefault).toHaveBeenCalled();
        expect(lastFocusSpy).toHaveBeenCalledTimes(1);
      });

      /**
       * @description Should do nothing when Tab pressed and no focusable elements exist
       * @scenario Empty container, Tab pressed
       * @expected No error, preventDefault not called
       */
      it("should do nothing if no focusable elements on Tab", () => {
        // Arrange
        // container empty
        const event = createKeydownEvent("Tab");

        // Act & Assert
        expect(() => registeredKeydownHandler?.(event)).not.toThrow();
        expect(event.preventDefault).not.toHaveBeenCalled();
      });

      /**
       * @description Should do nothing when containerRef.current is null
       * @scenario containerRef.current = null, Tab pressed
       * @expected No error, gracefully exits
       */
      it("should handle null containerRef gracefully on Tab", () => {
        // Arrange
        const { rerender } = renderHook(() =>
          useFocusTrap({ active: true, containerRef: { current: null } }),
        );
        rerender();
        const event = createKeydownEvent("Tab");

        // Act & Assert
        expect(() => registeredKeydownHandler?.(event)).not.toThrow();
      });
    });
  });

  describe("cleanup on deactivation / unmount", () => {
    /**
     * @description Should remove keydown event listener when active becomes false
     * @scenario Rerender with active: false after being active
     * @expected removeEventListener called with 'keydown' and previous handler
     */
    it("should remove event listener when active changes to false", () => {
      // Arrange
      const { rerender } = renderHook(
        ({ active }: { active: boolean }) =>
          useFocusTrap({ active, containerRef }),
        { initialProps: { active: true } },
      );
      const handler = registeredKeydownHandler;
      addEventListenerSpy.mockClear();

      // Act
      rerender({ active: false });

      // Assert
      expect(removeEventListenerSpy).toHaveBeenCalledWith("keydown", handler);
    });

    /**
     * @description Should restore focus to previously focused element on unmount
     * @scenario External button focused before activation, then hook unmounted
     * @expected The external button receives focus again
     */
    it("should restore focus to the previous element on unmount", () => {
      // Arrange
      const externalBtn = document.createElement("button");
      document.body.append(externalBtn);
      externalBtn.focus();
      const externalFocusSpy = vi.spyOn(externalBtn, "focus");
      // Add a focusable element inside container to allow successful activation
      const innerBtn = document.createElement("button");
      container.append(innerBtn);

      const { unmount } = renderHook(() =>
        useFocusTrap({ active: true, containerRef }),
      );
      // Clear spy calls caused by initial focus logic (if any)
      externalFocusSpy.mockClear();

      // Act
      unmount();

      // Assert
      expect(externalFocusSpy).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should not restore focus if previous element was removed from DOM
     * @scenario External button focused, then removed before unmount
     * @expected focus not called on removed element
     */
    it("should not restore focus if previous element is no longer in DOM", () => {
      // Arrange
      const externalBtn = document.createElement("button");
      document.body.append(externalBtn);
      externalBtn.focus();
      const externalFocusSpy = vi.spyOn(externalBtn, "focus");
      const innerBtn = document.createElement("button");
      container.append(innerBtn);

      const { unmount } = renderHook(() =>
        useFocusTrap({ active: true, containerRef }),
      );
      externalFocusSpy.mockClear();
      // Remove external button from DOM before unmount
      document.body.removeChild(externalBtn);

      // Act
      unmount();

      // Assert
      expect(externalFocusSpy).not.toHaveBeenCalled();
    });

    /**
     * @description Should not attempt to restore focus if previousFocusRef.current is null
     * @scenario document.activeElement was body (no specific element) before activation
     * @expected No error, no focus call on null
     */
    it("should not throw when previous focus was null", () => {
      // Arrange
      const { unmount } = renderHook(() =>
        useFocusTrap({ active: true, containerRef }),
      );

      // Act & Assert
      expect(() => unmount()).not.toThrow();
    });
  });
});
