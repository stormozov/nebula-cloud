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

import { useClickOutside } from "@/shared/hooks/useClickOutside";

import { useDropdownMenu } from "../useDropdownMenu";

vi.mock("@/shared/hooks/useClickOutside");

describe("useDropdownMenu", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("uncontrolled mode", () => {
    /**
     * @description Should initialize with isOpen = false by default
     * @scenario Hook is called without any props
     * @expected isOpen is false, menuRef is defined, close/toggle/setOpen are functions
     */
    it("should initialize with isOpen = false", () => {
      // Arrange & Act
      const { result } = renderHook(() => useDropdownMenu());

      // Assert
      expect(result.current.isOpen).toBe(false);
      expect(result.current.menuRef.current).toBeNull();
      expect(typeof result.current.setOpen).toBe("function");
      expect(typeof result.current.close).toBe("function");
      expect(typeof result.current.toggle).toBe("function");
      expect(typeof result.current.closeAndRestoreFocus).toBe("function");
    });

    /**
     * @description Should open dropdown when setOpen(true) is called
     * @scenario Call setOpen(true) in uncontrolled mode
     * @expected isOpen becomes true
     */
    it("should open dropdown when setOpen(true) is called", () => {
      // Arrange
      const { result } = renderHook(() => useDropdownMenu());

      // Act
      act(() => {
        result.current.setOpen(true);
      });

      // Assert
      expect(result.current.isOpen).toBe(true);
    });

    /**
     * @description Should close dropdown when setOpen(false) is called
     * @scenario Call setOpen(false) after opening
     * @expected isOpen becomes false
     */
    it("should close dropdown when setOpen(false) is called", () => {
      // Arrange
      const { result } = renderHook(() => useDropdownMenu());

      // Act
      act(() => {
        result.current.setOpen(true);
        result.current.setOpen(false);
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
    });

    /**
     * @description Should toggle dropdown state when toggle() is called
     * @scenario Call toggle() twice
     * @expected isOpen toggles from false to true then to false
     */
    it("should toggle dropdown state when toggle() is called", () => {
      // Arrange
      const { result } = renderHook(() => useDropdownMenu());

      // Act & Assert
      act(() => {
        result.current.toggle();
      });
      expect(result.current.isOpen).toBe(true);

      act(() => {
        result.current.toggle();
      });
      expect(result.current.isOpen).toBe(false);
    });

    /**
     * @description Should close dropdown when close() is called
     * @scenario Open dropdown then call close()
     * @expected isOpen becomes false
     */
    it("should close dropdown when close() is called", () => {
      // Arrange
      const { result } = renderHook(() => useDropdownMenu());

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      // Act
      act(() => {
        result.current.close();
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
    });

    /**
     * @description Should restore focus to previously focused element after closing
     * @scenario Call closeAndRestoreFocus() when dropdown is open
     * @expected Focus is restored after a microtask (setTimeout)
     */
    it("should restore focus to previously focused element when closeAndRestoreFocus is called", () => {
      // Arrange
      const { result } = renderHook(() => useDropdownMenu());
      const mockFocus = vi.fn();
      const dummyElement = document.createElement("button");
      dummyElement.focus = mockFocus;
      vi.spyOn(document, "activeElement", "get").mockReturnValue(dummyElement);

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      // Act
      act(() => {
        result.current.closeAndRestoreFocus();
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
      vi.advanceTimersByTime(0);
      expect(mockFocus).toHaveBeenCalled();
    });

    /**
     * @description Should capture activeElement when dropdown opens
     * @scenario Open dropdown and then closeAndRestoreFocus
     * @expected Focus restores to the element that was active at open time
     */
    it("should capture activeElement on open and restore it on closeAndRestoreFocus", () => {
      // Arrange
      const { result } = renderHook(() => useDropdownMenu());
      const button = document.createElement("button");
      button.focus = vi.fn();
      document.body.appendChild(button);
      button.focus();

      // Act
      act(() => {
        result.current.setOpen(true);
      });
      // change active element while dropdown is open
      const input = document.createElement("input");
      input.focus();
      document.body.appendChild(input);
      input.focus();

      act(() => {
        result.current.closeAndRestoreFocus();
      });

      // Assert
      vi.advanceTimersByTime(0);
      expect(button.focus).toHaveBeenCalled();

      // Cleanup
      document.body.removeChild(button);
      document.body.removeChild(input);
    });

    /**
     * @description Should not call onOpenChange when not provided
     * @scenario Toggle open state without onOpenChange prop
     * @expected No error, internal state updates
     */
    it("should work without onOpenChange callback", () => {
      // Arrange & Act
      const { result } = renderHook(() => useDropdownMenu());

      // Assert
      expect(() => {
        act(() => {
          result.current.setOpen(true);
        });
      }).not.toThrow();
      expect(result.current.isOpen).toBe(true);
    });
  });

  describe("controlled mode", () => {
    /**
     * @description Should respect isOpenControlled prop and call onOpenChange
     * @scenario Pass isOpenControlled=true and onOpenChange mock, then call setOpen(false)
     * @expected isOpen remains true, onOpenChange called with false
     */
    it("should respect isOpenControlled and not change internal state", () => {
      // Arrange
      const onOpenChange = vi.fn();
      const { result } = renderHook(() =>
        useDropdownMenu({ isOpenControlled: true, onOpenChange }),
      );

      // Act
      act(() => {
        result.current.setOpen(false);
      });

      // Assert
      expect(result.current.isOpen).toBe(true); // controlled by prop
      expect(onOpenChange).toHaveBeenCalledWith(false);
    });

    /**
     * @description Should call onOpenChange when toggle is called in controlled mode
     * @scenario Pass isOpenControlled=false and onOpenChange, call toggle
     * @expected onOpenChange called with true
     */
    it("should call onOpenChange with opposite value when toggle is called", () => {
      // Arrange
      const onOpenChange = vi.fn();
      const { result } = renderHook(() =>
        useDropdownMenu({ isOpenControlled: false, onOpenChange }),
      );

      // Act
      act(() => {
        result.current.toggle();
      });

      // Assert
      expect(onOpenChange).toHaveBeenCalledWith(true);
    });

    /**
     * @description Should call onOpenChange when close() is called
     * @scenario Controlled with isOpenControlled=true, call close()
     * @expected onOpenChange called with false
     */
    it("should call onOpenChange with false when close() is called", () => {
      // Arrange
      const onOpenChange = vi.fn();
      const { result } = renderHook(() =>
        useDropdownMenu({ isOpenControlled: true, onOpenChange }),
      );

      // Act
      act(() => {
        result.current.close();
      });

      // Assert
      expect(onOpenChange).toHaveBeenCalledWith(false);
    });
  });

  describe("closeOnClickOutside behaviour", () => {
    /**
     * @description Should close dropdown when click outside occurs and closeOnClickOutside=true
     * @scenario Render hook with closeOnClickOutside=true, open dropdown, simulate click outside via useClickOutside callback
     * @expected close() is called and isOpen becomes false
     */
    it("should close dropdown when click outside occurs if closeOnClickOutside is true", () => {
      // Arrange
      let clickOutsideCallback: (() => void) | undefined;
      (useClickOutside as Mock).mockImplementation((_ref, callback) => {
        clickOutsideCallback = callback;
      });

      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnClickOutside: true }),
      );

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      // Act
      act(() => {
        clickOutsideCallback?.();
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
    });

    /**
     * @description Should not close dropdown when click outside occurs if closeOnClickOutside=false
     * @scenario Set closeOnClickOutside=false, open dropdown, trigger click outside callback
     * @expected isOpen remains true
     */
    it("should not close dropdown when click outside occurs if closeOnClickOutside is false", () => {
      // Arrange
      let clickOutsideCallback: (() => void) | undefined;
      (useClickOutside as Mock).mockImplementation((_ref, callback) => {
        clickOutsideCallback = callback;
      });

      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnClickOutside: false }),
      );

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      // Act
      act(() => {
        clickOutsideCallback?.();
      });

      // Assert
      expect(result.current.isOpen).toBe(true);
    });

    /**
     * @description Should restore focus after click outside closes dropdown
     * @scenario open dropdown, click outside when closeOnClickOutside=true, and triggerRef exists
     * @expected focus is restored after setTimeout
     */
    it("should restore focus after click outside closes dropdown", () => {
      // Arrange
      let clickOutsideCallback: (() => void) | undefined;
      (useClickOutside as Mock).mockImplementation((_ref, callback) => {
        clickOutsideCallback = callback;
      });

      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnClickOutside: true }),
      );
      const mockFocus = vi.fn();
      const trigger = document.createElement("button");
      trigger.focus = mockFocus;

      // Simulate triggerRef being set internally when dropdown opens
      vi.spyOn(document, "activeElement", "get").mockReturnValue(trigger);

      act(() => {
        result.current.setOpen(true);
      });

      // Act
      act(() => {
        clickOutsideCallback?.();
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
      vi.advanceTimersByTime(0);
      expect(mockFocus).toHaveBeenCalled();
    });
  });

  describe("closeOnEscape behaviour", () => {
    /**
     * @description Should close dropdown when Escape key is pressed and closeOnEscape=true
     * @scenario open dropdown, dispatch Escape keyboard event
     * @expected isOpen becomes false, focus restored
     */
    it("should close dropdown when Escape key is pressed if closeOnEscape is true", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: true }),
      );
      const mockFocus = vi.fn();
      const trigger = document.createElement("button");
      trigger.focus = mockFocus;
      vi.spyOn(document, "activeElement", "get").mockReturnValue(trigger);

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      // Act
      act(() => {
        const event = new KeyboardEvent("keydown", { key: "Escape" });
        document.dispatchEvent(event);
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
      vi.advanceTimersByTime(0);
      expect(mockFocus).toHaveBeenCalled();
    });

    /**
     * @description Should not close dropdown when Escape key is pressed if closeOnEscape=false
     * @scenario open dropdown, set closeOnEscape=false, dispatch Escape event
     * @expected isOpen remains true
     */
    it("should not close dropdown when Escape key is pressed if closeOnEscape is false", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: false }),
      );

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      // Act
      act(() => {
        const event = new KeyboardEvent("keydown", { key: "Escape" });
        document.dispatchEvent(event);
      });

      // Assert
      expect(result.current.isOpen).toBe(true);
    });

    /**
     * @description Should prevent default Escape behavior to avoid browser back/close
     * @scenario open dropdown, dispatch Escape event
     * @expected event.preventDefault is called
     */
    it("should call preventDefault on Escape keydown when dropdown is open", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: true }),
      );

      act(() => {
        result.current.setOpen(true);
      });

      // Act
      const event = new KeyboardEvent("keydown", { key: "Escape" });
      const preventDefaultSpy = vi.spyOn(event, "preventDefault");
      document.dispatchEvent(event);

      // Assert
      expect(preventDefaultSpy).toHaveBeenCalled();
    });

    /**
     * @description Should not add Escape listener if closeOnEscape is false
     * @scenario set closeOnEscape=false, open dropdown
     * @expected no keyboard event handler attached (implicitly tested by lack of closing)
     */
    it("should not close on Escape when closeOnEscape is initially false", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: false }),
      );

      act(() => {
        result.current.setOpen(true);
      });

      // Act
      act(() => {
        const event = new KeyboardEvent("keydown", { key: "Escape" });
        document.dispatchEvent(event);
      });

      // Assert
      expect(result.current.isOpen).toBe(true);
    });
  });

  describe("useClickOutside integration", () => {
    /**
     * @description Should register click outside handler with menuRef
     * @scenario Call useDropdownMenu and verify useClickOutside is called with menuRef and a callback
     * @expected useClickOutside is called with menuRef and a function
     */
    it("should call useClickOutside with menuRef and a callback", () => {
      // Arrange
      (useClickOutside as Mock).mockClear();

      // Act
      renderHook(() => useDropdownMenu());

      // Assert
      expect(useClickOutside).toHaveBeenCalledTimes(1);
      const [ref, callback] = (useClickOutside as Mock).mock.calls[0];
      expect(ref.current).toBeNull(); // ref is passed, current is null initially
      expect(typeof callback).toBe("function");
    });

    /**
     * @description Should not call close if click outside occurs when dropdown is closed
     * @scenario Simulate click outside callback when isOpen=false
     * @expected close not triggered (no state change)
     */
    it("should not close when click outside occurs and dropdown is already closed", () => {
      // Arrange
      let clickOutsideCallback: (() => void) | undefined;
      (useClickOutside as Mock).mockImplementation((_ref, callback) => {
        clickOutsideCallback = callback;
      });

      const { result } = renderHook(() => useDropdownMenu());
      expect(result.current.isOpen).toBe(false);

      // Act
      act(() => {
        clickOutsideCallback?.();
      });

      // Assert
      expect(result.current.isOpen).toBe(false);
    });
  });

  describe("useDropdownMenu - Escape key handler edge cases", () => {
    /**
     * @description Should not close when Escape is pressed but dropdown is closed
     * @scenario Dropdown is closed (isOpen=false), dispatch Escape keydown event
     * @expected closeAndRestoreFocus is not called, isOpen remains false
     */
    it("should not call closeAndRestoreFocus when Escape is pressed and dropdown is closed", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: true }),
      );
      expect(result.current.isOpen).toBe(false);

      const closeAndRestoreFocusSpy = vi.spyOn(
        result.current,
        "closeAndRestoreFocus",
      );

      // Act
      act(() => {
        const event = new KeyboardEvent("keydown", { key: "Escape" });
        document.dispatchEvent(event);
      });

      // Assert
      expect(closeAndRestoreFocusSpy).not.toHaveBeenCalled();
      expect(result.current.isOpen).toBe(false);
    });

    /**
     * @description Should not close when non-Escape key is pressed while dropdown is open
     * @scenario Open dropdown, dispatch keydown event with key='Enter'
     * @expected closeAndRestoreFocus not called, isOpen remains true
     */
    it("should not close when non-Escape key is pressed and dropdown is open", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: true }),
      );

      act(() => {
        result.current.setOpen(true);
      });
      expect(result.current.isOpen).toBe(true);

      const closeAndRestoreFocusSpy = vi.spyOn(
        result.current,
        "closeAndRestoreFocus",
      );

      // Act
      act(() => {
        const event = new KeyboardEvent("keydown", { key: "Enter" });
        document.dispatchEvent(event);
      });

      // Assert
      expect(closeAndRestoreFocusSpy).not.toHaveBeenCalled();
      expect(result.current.isOpen).toBe(true);
    });

    /**
     * @description Should call preventDefault only for Escape key, not for other keys
     * @scenario Open dropdown, dispatch Escape and then Enter events
     * @expected preventDefault called for Escape, not called for Enter
     */
    it("should call preventDefault for Escape key but not for other keys", () => {
      // Arrange
      const { result } = renderHook(() =>
        useDropdownMenu({ closeOnEscape: true }),
      );

      act(() => {
        result.current.setOpen(true);
      });

      // Act & Assert for Escape
      const escapeEvent = new KeyboardEvent("keydown", { key: "Escape" });
      const escapePreventDefaultSpy = vi.spyOn(escapeEvent, "preventDefault");
      document.dispatchEvent(escapeEvent);
      expect(escapePreventDefaultSpy).toHaveBeenCalled();

      // Act & Assert for Enter
      const enterEvent = new KeyboardEvent("keydown", { key: "Enter" });
      const enterPreventDefaultSpy = vi.spyOn(enterEvent, "preventDefault");
      document.dispatchEvent(enterEvent);
      expect(enterPreventDefaultSpy).not.toHaveBeenCalled();
    });
  });
});
