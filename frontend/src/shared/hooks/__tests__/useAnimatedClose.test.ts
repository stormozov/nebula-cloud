import { act, renderHook } from "@testing-library/react";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  vi,
} from "vitest";

import { useAnimatedClose } from "../useAnimatedClose";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const createProps = (overrides = {}) => ({
  onClose: vi.fn(),
  isBlocked: false,
  animationDuration: 300,
  ...overrides,
});

// ---------------------------------------------------------------------------
// useAnimatedClose tests
// ---------------------------------------------------------------------------
describe("useAnimatedClose", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(window, "addEventListener");
    vi.spyOn(window, "removeEventListener");
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // initialization
  // -------------------------------------------------------------------------
  describe("initial state", () => {
    /**
     * @description Should return isClosing false and a function
     * @scenario Hook is rendered with default props
     * @expected isClosing is false, handleCloseWithAnimation is a function
     */
    it("should return isClosing false and handleCloseWithAnimation function", () => {
      // Arrange
      const props = createProps();

      // Act
      const { result } = renderHook(() => useAnimatedClose(props));

      // Assert
      expect(result.current.isClosing).toBe(false);
      expect(typeof result.current.handleCloseWithAnimation).toBe("function");
    });
  });

  // -------------------------------------------------------------------------
  // handleCloseWithAnimation
  // -------------------------------------------------------------------------
  describe("handleCloseWithAnimation", () => {
    /**
     * @description Should start closing animation and call onClose after duration
     * @scenario Call handleCloseWithAnimation when not blocked and not already closing
     * @expected setIsClosing(true), timeout set, onClose called after animationDuration
     */
    it("should set isClosing true and call onClose after animation duration", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose, animationDuration: 500 });
      const { result } = renderHook(() => useAnimatedClose(props));

      // Act
      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Assert
      expect(result.current.isClosing).toBe(true);

      // Advance time less than duration -> onClose not called
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(onClose).not.toHaveBeenCalled();
      expect(result.current.isClosing).toBe(true);

      // Advance remaining time
      act(() => {
        vi.advanceTimersByTime(100);
      });
      expect(onClose).toHaveBeenCalledTimes(1);
      expect(result.current.isClosing).toBe(false);
    });

    /**
     * @description Should not start closing if already closing
     * @scenario Call handleCloseWithAnimation while isClosing is true
     * @expected No new timeout, onClose not called again prematurely
     */
    it("should do nothing if already closing", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose });
      const { result } = renderHook(() => useAnimatedClose(props));

      // Start first close
      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Attempt second call while closing
      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Advance full duration
      act(() => {
        vi.advanceTimersByTime(300);
      });

      // Assert
      expect(onClose).toHaveBeenCalledTimes(1); // only one close triggered
    });

    /**
     * @description Should not start closing if blocked
     * @scenario isBlocked = true
     * @expected isClosing stays false, onClose not called
     */
    it("should do nothing when isBlocked is true", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose, isBlocked: true });
      const { result } = renderHook(() => useAnimatedClose(props));

      // Act
      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Assert
      expect(result.current.isClosing).toBe(false);

      act(() => {
        vi.advanceTimersByTime(300);
      });
      expect(onClose).not.toHaveBeenCalled();
    });

    /**
     * @description Should cleanup timeout if component unmounts before animation ends
     * @scenario Start closing, then unmount hook
     * @expected onClose not called, clearTimeout invoked
     */
    it("should clear timeout on unmount", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose });
      const { result, unmount } = renderHook(() => useAnimatedClose(props));

      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Act
      unmount();

      act(() => {
        vi.advanceTimersByTime(300);
      });

      // Assert
      expect(onClose).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // ESC key handling
  // -------------------------------------------------------------------------
  describe("ESC key handling", () => {
    /**
     * @description Should trigger close on ESC press when not blocked
     * @scenario Simulate keydown event with key 'Escape', isBlocked false
     * @expected preventDefault called, handleCloseWithAnimation invoked
     */
    it("should close on ESC when not blocked", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose });
      renderHook(() => useAnimatedClose(props));

      // Act
      act(() => {
        const event = new KeyboardEvent("keydown", { key: "Escape" });
        vi.spyOn(event, "preventDefault");
        window.dispatchEvent(event);

        vi.advanceTimersByTime(300);
      });

      // Assert
      expect(onClose).toHaveBeenCalledTimes(1);
      const addCall = (window.addEventListener as Mock).mock.calls[0];
      expect(addCall[0]).toBe("keydown");
      const handler = addCall[1];
      // We can also assert preventDefault was called inside the handler
      // But easier is to check that the event was prevented:
      const event = new KeyboardEvent("keydown", {
        key: "Escape",
        cancelable: true,
      });
      const preventSpy = vi.spyOn(event, "preventDefault");
      handler(event);
      expect(preventSpy).toHaveBeenCalled();
    });

    /**
     * @description Should not close on ESC when blocked
     * @scenario isBlocked = true
     * @expected Event listener exists but does not call onClose
     */
    it("should not close on ESC when isBlocked is true", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose, isBlocked: true });
      renderHook(() => useAnimatedClose(props));

      // Act
      act(() => {
        window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
        vi.advanceTimersByTime(300);
      });

      // Assert
      expect(onClose).not.toHaveBeenCalled();
    });

    /**
     * @description Should ignore other keys
     * @scenario Press Enter key
     * @expected onClose not called
     */
    it("should not react to non-Escape keys", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose });
      renderHook(() => useAnimatedClose(props));

      // Act
      act(() => {
        window.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
        vi.advanceTimersByTime(300);
      });

      // Assert
      expect(onClose).not.toHaveBeenCalled();
    });

    /**
     * @description Should remove event listener on unmount
     * @scenario Render hook, then unmount
     * @expected removeEventListener called with same handler
     */
    it("should remove keydown listener on unmount", () => {
      // Arrange
      const props = createProps();
      const { unmount } = renderHook(() => useAnimatedClose(props));

      // Act
      unmount();

      // Assert
      expect(window.removeEventListener).toHaveBeenCalledWith(
        "keydown",
        expect.any(Function),
      );

      // Specifically, the same function that was added
      const addCall = (window.addEventListener as Mock).mock.calls[0];
      const removeCall = (window.removeEventListener as Mock).mock.calls[0];
      expect(removeCall[0]).toBe("keydown");
      expect(removeCall[1]).toBe(addCall[1]);
    });
  });

  // -------------------------------------------------------------------------
  // edge cases
  // -------------------------------------------------------------------------
  describe("edge cases", () => {
    /**
     * @description Should update isBlocked dynamically and prevent closing
     * @scenario Start unblocked, then pass isBlocked true before ESC
     * @expected Latest isBlocked value used
     */
    it("should respect updated isBlocked prop", () => {
      // Arrange
      const onClose = vi.fn();
      const { result, rerender } = renderHook(
        (props) => useAnimatedClose(props),
        { initialProps: { onClose, isBlocked: false } },
      );

      // Act: block
      rerender({ onClose, isBlocked: true });

      act(() => {
        result.current.handleCloseWithAnimation();
      });

      // Assert
      expect(result.current.isClosing).toBe(false);

      act(() => {
        vi.advanceTimersByTime(300);
      });
      expect(onClose).not.toHaveBeenCalled();
    });

    /**
     * @description Should finish closing and allow new close after timeout completes
     * @scenario Trigger close, wait for animation, then trigger close again
     * @expected Both onClose calls happen independently
     */
    it("should allow new close after animation completes", () => {
      // Arrange
      const onClose = vi.fn();
      const props = createProps({ onClose });
      const { result } = renderHook(() => useAnimatedClose(props));

      // First close
      act(() => {
        result.current.handleCloseWithAnimation();
      });
      act(() => {
        vi.advanceTimersByTime(300);
      });
      expect(onClose).toHaveBeenCalledTimes(1);

      // Second close
      act(() => {
        result.current.handleCloseWithAnimation();
      });
      act(() => {
        vi.advanceTimersByTime(300);
      });

      expect(onClose).toHaveBeenCalledTimes(2);
    });
  });
});
