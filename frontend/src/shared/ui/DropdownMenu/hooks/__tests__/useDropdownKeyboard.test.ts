import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DropdownMenuItem, IDropdownMenuActionItem } from "../../types";
import { useDropdownKeyboard } from "../useDropdownKeyboard";

describe("useDropdownKeyboard", () => {
  const createActionItem = (
    id: string,
    disabled?: boolean | ((item: unknown) => boolean),
  ): IDropdownMenuActionItem<unknown> => ({
    id,
    label: `Action ${id}`,
    onClick: vi.fn(),
    disabled,
  });

  const nonActionItem: DropdownMenuItem<unknown> = {
    type: "separator",
    id: "separator",
  };

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("when dropdown opens", () => {
    /**
     * @description Should filter only action items (with onClick) from mixed items array
     * @scenario Pass items containing both action items and separator items, isOpen=false then isOpen=true
     * @expected focusedIndex should be set to first enabled action item index (skipping separators)
     */
    it("should filter only action items and focus first enabled action", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        nonActionItem,
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };

      // Act
      const { result, rerender } = renderHook(
        ({ isOpen }) =>
          useDropdownKeyboard({
            isOpen,
            items,
            item: mockItem,
            onClose: vi.fn(),
            onSelect: vi.fn(),
          }),
        { initialProps: { isOpen: false } },
      );

      expect(result.current.focusedIndex).toBe(-1);

      rerender({ isOpen: true });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });

    /**
     * @description Should focus on first enabled action when dropdown opens, skipping disabled actions
     * @scenario First action disabled, second enabled, isOpen toggled to true
     * @expected focusedIndex = 1 (second action)
     */
    it("should focus on first enabled action, skipping disabled ones", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", true),
        createActionItem("action2", false),
      ];
      const mockItem = { id: 1 };

      // Act
      const { result, rerender } = renderHook(
        ({ isOpen }) =>
          useDropdownKeyboard({
            isOpen,
            items,
            item: mockItem,
            onClose: vi.fn(),
            onSelect: vi.fn(),
          }),
        { initialProps: { isOpen: false } },
      );

      rerender({ isOpen: true });

      // Assert
      expect(result.current.focusedIndex).toBe(1);
    });

    /**
     * @description Should not set focused index if all actions are disabled
     * @scenario Pass all actions with disabled=true, open dropdown
     * @expected focusedIndex remains -1
     */
    it("should not set focused index when all actions are disabled", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", true),
        createActionItem("action2", true),
      ];
      const mockItem = { id: 1 };

      // Act
      const { result, rerender } = renderHook(
        ({ isOpen }) =>
          useDropdownKeyboard({
            isOpen,
            items,
            item: mockItem,
            onClose: vi.fn(),
            onSelect: vi.fn(),
          }),
        { initialProps: { isOpen: false } },
      );

      rerender({ isOpen: true });

      // Assert
      expect(result.current.focusedIndex).toBe(-1);
    });

    /**
     * @description Should try to focus action element with requestAnimationFrame fallback
     * @scenario Open dropdown, simulate ref not immediately available
     * @expected focus called after retry
     */
    it("should retry focusing until element is available", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [createActionItem("action1")];
      const mockItem = { id: 1 };
      const mockFocus = vi.fn();
      const mockRef = { focus: mockFocus };

      const { result, rerender } = renderHook(
        ({ isOpen }) =>
          useDropdownKeyboard({
            isOpen,
            items,
            item: mockItem,
            onClose: vi.fn(),
            onSelect: vi.fn(),
          }),
        { initialProps: { isOpen: false } },
      );

      rerender({ isOpen: true });

      // Simulate ref being set after the first requestAnimationFrame
      act(() => {
        result.current.actionRefs.current[0] =
          mockRef as unknown as HTMLButtonElement;
      });

      // Advance timers to execute the queued requestAnimationFrame callbacks
      vi.runOnlyPendingTimers();

      // Assert
      expect(mockFocus).toHaveBeenCalledWith({ preventScroll: true });
    });
  });

  describe("ArrowDown navigation", () => {
    /**
     * @description Should move focus to next enabled action when ArrowDown pressed
     * @scenario Open dropdown with two enabled actions, focusedIndex=0, press ArrowDown
     * @expected focusedIndex becomes 1, and focus is called on next element
     */
    it("should move focus to next enabled action on ArrowDown", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };
      const onClose = vi.fn();
      const onSelect = vi.fn();
      const mockFocus = vi.fn();
      const mockRefs = [
        { focus: mockFocus },
        { focus: mockFocus },
      ] as unknown as HTMLButtonElement[];

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose,
          onSelect,
        }),
      );

      act(() => {
        result.current.actionRefs.current = mockRefs;
        result.current.actionRefs.current[0] = mockRefs[0];
        result.current.actionRefs.current[1] = mockRefs[1];
      });

      expect(result.current.focusedIndex).toBe(0);

      // Act
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(1);
      expect(mockRefs[1].focus).toHaveBeenCalledWith({ preventScroll: true });
    });

    /**
     * @description Should wrap around to first enabled action when ArrowDown at last item
     * @scenario Navigate to last item using ArrowDown, then press ArrowDown again
     * @expected focusedIndex wraps to first enabled action
     */
    it("should wrap to first enabled action when ArrowDown on last item", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // First press: move from 0 -> 1
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });
      expect(result.current.focusedIndex).toBe(1);

      // Act: second press, should wrap to 0
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });

    /**
     * @description Should skip disabled actions when navigating with ArrowDown
     * @scenario Actions: [enabled, disabled, enabled], focusedIndex=0, press ArrowDown
     * @expected focusedIndex jumps to 2 (skip disabled at index 1)
     */
    it("should skip disabled actions on ArrowDown", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", false),
        createActionItem("action2", true),
        createActionItem("action3", false),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      expect(result.current.focusedIndex).toBe(0);

      // Act
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(2);
    });

    /**
     * @description Should not change focus if only one enabled action and ArrowDown pressed
     * @scenario Single enabled action, focusedIndex=0, press ArrowDown
     * @expected focusedIndex remains 0
     */
    it("should not change focus when only one enabled action exists on ArrowDown", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [createActionItem("action1")];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      expect(result.current.focusedIndex).toBe(0);

      // Act
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });
  });

  describe("ArrowUp navigation", () => {
    /**
     * @description Should move focus to previous enabled action when ArrowUp pressed
     * @scenario Navigate to second item via ArrowDown, then press ArrowUp
     * @expected focusedIndex becomes 0
     */
    it("should move focus to previous enabled action on ArrowUp", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // Navigate to index 1
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });
      expect(result.current.focusedIndex).toBe(1);

      // Act
      act(() => {
        const event = {
          key: "ArrowUp",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });

    /**
     * @description Should wrap to last enabled action when ArrowUp on first item
     * @scenario focusedIndex=0, press ArrowUp
     * @expected focusedIndex becomes last enabled action index
     */
    it("should wrap to last enabled action when ArrowUp on first item", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
        createActionItem("action3"),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      expect(result.current.focusedIndex).toBe(0);

      // Act
      act(() => {
        const event = {
          key: "ArrowUp",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(2);
    });

    /**
     * @description Should skip disabled actions when navigating with ArrowUp
     * @scenario Actions: [enabled, disabled, enabled], navigate to last enabled (index 2), press ArrowUp
     * @expected focusedIndex jumps to 0 (skip disabled at index 1)
     */
    it("should skip disabled actions on ArrowUp", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", false),
        createActionItem("action2", true),
        createActionItem("action3", false),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // Navigate to last enabled (index 2) via ArrowDown twice
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });
      expect(result.current.focusedIndex).toBe(2);

      // Act
      act(() => {
        const event = {
          key: "ArrowUp",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });
  });

  describe("Enter and Space selection", () => {
    /**
     * @description Should call onSelect with selected action and onClose on Enter key
     * @scenario focusedIndex=0, press Enter
     * @expected onSelect called with action, onClose called
     */
    it("should call onSelect and onClose when Enter is pressed on enabled action", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [createActionItem("action1")];
      const mockItem = { id: 1 };
      const onClose = vi.fn();
      const onSelect = vi.fn();

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose,
          onSelect,
        }),
      );

      // Act
      act(() => {
        const event = {
          key: "Enter",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(onSelect).toHaveBeenCalledWith(items[0]);
      expect(onClose).toHaveBeenCalled();
    });

    /**
     * @description Should call onSelect and onClose when Space is pressed on enabled action
     * @scenario focusedIndex=0, press Space
     * @expected onSelect called with action, onClose called
     */
    it("should call onSelect and onClose when Space is pressed on enabled action", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [createActionItem("action1")];
      const mockItem = { id: 1 };
      const onClose = vi.fn();
      const onSelect = vi.fn();

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose,
          onSelect,
        }),
      );

      // Act
      act(() => {
        const event = {
          key: " ",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(onSelect).toHaveBeenCalledWith(items[0]);
      expect(onClose).toHaveBeenCalled();
    });

    /**
     * @description Should not select disabled action on Enter
     * @scenario All actions disabled, focusedIndex=-1, press Enter
     * @expected onSelect not called, onClose not called
     */
    it("should not select disabled action when Enter pressed", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", true),
      ];
      const mockItem = { id: 1 };
      const onClose = vi.fn();
      const onSelect = vi.fn();

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose,
          onSelect,
        }),
      );

      // focusedIndex should be -1 because action is disabled
      expect(result.current.focusedIndex).toBe(-1);

      // Act
      act(() => {
        const event = {
          key: "Enter",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(onSelect).not.toHaveBeenCalled();
      expect(onClose).not.toHaveBeenCalled();
    });

    /**
     * @description Should do nothing when focusedIndex = -1 and Enter pressed
     * @scenario No action focused (all disabled), press Enter
     * @expected onSelect not called
     */
    it("should not select when focusedIndex is -1 and Enter pressed", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", true),
      ];
      const mockItem = { id: 1 };
      const onClose = vi.fn();
      const onSelect = vi.fn();

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose,
          onSelect,
        }),
      );

      expect(result.current.focusedIndex).toBe(-1);

      // Act
      act(() => {
        const event = {
          key: "Enter",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(onSelect).not.toHaveBeenCalled();
      expect(onClose).not.toHaveBeenCalled();
    });
  });

  describe("Tab navigation", () => {
    /**
     * @description Should move focus to next action on Tab press (without Shift)
     * @scenario Press Tab, focusedIndex=0
     * @expected focusedIndex becomes 1
     */
    it("should move focus to next action on Tab", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      expect(result.current.focusedIndex).toBe(0);

      // Act
      act(() => {
        const event = {
          key: "Tab",
          shiftKey: false,
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(1);
    });

    /**
     * @description Should move focus to previous action on Tab with Shift
     * @scenario Navigate to second item via Tab, then press Shift+Tab
     * @expected focusedIndex becomes 0
     */
    it("should move focus to previous action on Shift+Tab", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // Navigate to index 1
      act(() => {
        const event = {
          key: "Tab",
          shiftKey: false,
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });
      expect(result.current.focusedIndex).toBe(1);

      // Act
      act(() => {
        const event = {
          key: "Tab",
          shiftKey: true,
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });

    /**
     * @description Should wrap around on Tab from last to first
     * @scenario Navigate to last action via Tab, then press Tab again
     * @expected focusedIndex wraps to first
     */
    it("should wrap to first action when Tab pressed on last action", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1"),
        createActionItem("action2"),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // Navigate to last item (index 1)
      act(() => {
        const event = {
          key: "Tab",
          shiftKey: false,
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });
      expect(result.current.focusedIndex).toBe(1);

      // Act: press Tab again
      act(() => {
        const event = {
          key: "Tab",
          shiftKey: false,
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(0);
    });

    /**
     * @description Should skip disabled actions on Tab navigation
     * @scenario Actions: [enabled, disabled, enabled], Tab from index 0
     * @expected focusedIndex jumps to 2 (skip disabled)
     */
    it("should skip disabled actions on Tab", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", false),
        createActionItem("action2", true),
        createActionItem("action3", false),
      ];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      expect(result.current.focusedIndex).toBe(0);

      // Act
      act(() => {
        const event = {
          key: "Tab",
          shiftKey: false,
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(2);
    });
  });

  describe("edge cases and no-ops", () => {
    /**
     * @description Should do nothing when dropdown is closed and key pressed
     * @scenario isOpen=false, press any key
     * @expected no state changes, no callbacks
     */
    it("should ignore keyboard events when dropdown is closed", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [createActionItem("action1")];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: false,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // Act
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(-1);
    });

    /**
     * @description Should do nothing when actionItems array is empty
     * @scenario items array has no action items (only separators), isOpen=true, press ArrowDown
     * @expected no errors, focusedIndex remains -1
     */
    it("should handle empty actionItems gracefully", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [nonActionItem];
      const mockItem = { id: 1 };
      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose: vi.fn(),
          onSelect: vi.fn(),
        }),
      );

      // Act
      act(() => {
        const event = {
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(result.current.focusedIndex).toBe(-1);
    });

    /**
     * @description Should handle disabled as function that receives current item
     * @scenario Pass disabled function that returns true/false based on item property
     * @expected disabled state correctly evaluated
     */
    it("should evaluate disabled function with current item", () => {
      // Arrange
      const mockItem = { id: 1, isAdmin: false };
      const items: DropdownMenuItem<unknown>[] = [
        createActionItem("action1", (item: unknown) => {
          return !(item as { isAdmin: boolean }).isAdmin;
        }),
      ];
      const onSelect = vi.fn();
      const onClose = vi.fn();

      const { result } = renderHook(() =>
        useDropdownKeyboard({
          isOpen: true,
          items,
          item: mockItem,
          onClose,
          onSelect,
        }),
      );

      // Since disabled returns true (isAdmin false), action should be disabled
      expect(result.current.focusedIndex).toBe(-1);

      // Act: try to select anyway (should not work)
      act(() => {
        const event = {
          key: "Enter",
          preventDefault: vi.fn(),
        } as unknown as React.KeyboardEvent;
        result.current.handleKeyDown(event);
      });

      // Assert
      expect(onSelect).not.toHaveBeenCalled();
      expect(onClose).not.toHaveBeenCalled();
    });

    /**
     * @description Should reset focusedIndex to -1 when dropdown closes
     * @scenario Open dropdown (focusedIndex set), then close it
     * @expected focusedIndex becomes -1
     */
    it("should reset focusedIndex to -1 when isOpen becomes false", () => {
      // Arrange
      const items: DropdownMenuItem<unknown>[] = [createActionItem("action1")];
      const mockItem = { id: 1 };
      const { result, rerender } = renderHook(
        ({ isOpen }) =>
          useDropdownKeyboard({
            isOpen,
            items,
            item: mockItem,
            onClose: vi.fn(),
            onSelect: vi.fn(),
          }),
        { initialProps: { isOpen: true } },
      );

      expect(result.current.focusedIndex).toBe(0);

      // Act
      rerender({ isOpen: false });

      // Assert
      expect(result.current.focusedIndex).toBe(-1);
    });
  });
});
