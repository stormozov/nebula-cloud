import { useCallback, useLayoutEffect, useMemo, useRef, useState } from "react";

import type { DropdownMenuItem, IDropdownMenuActionItem } from "../types";

/**
 * Properties for the `useDropdownKeyboard` hook.
 */
interface UseDropdownKeyboardOptions<T> {
  /** Whether the dropdown menu is open */
  isOpen: boolean;
  /** Dropdown menu actions */
  items: DropdownMenuItem<T>[];
  /** Item associated with the dropdown */
  item: T;
  /** Callback to close the dropdown */
  onClose: () => void;
  /** Callback to handle action selection */
  onSelect: (action: IDropdownMenuActionItem<T>) => void;
}

/**
 * Hook for managing keyboard navigation within a dropdown menu.
 *
 * Handles arrow keys (`up/down`), `Enter/Space` selection, and focus management
 */
export function useDropdownKeyboard<T>({
  isOpen,
  items,
  item,
  onClose,
  onSelect,
}: UseDropdownKeyboardOptions<T>) {
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const actionRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const actionItems = useMemo(
    () =>
      items.filter(
        (it): it is IDropdownMenuActionItem<T> =>
          (it as IDropdownMenuActionItem<T>).onClick !== undefined,
      ),
    [items],
  );

  const getFirstEnabledIndex = useCallback(() => {
    return actionItems.findIndex((action) => {
      const disabled =
        typeof action.disabled === "function"
          ? action.disabled(item)
          : action.disabled;
      return !disabled;
    });
  }, [actionItems, item]);

  useLayoutEffect(() => {
    if (!isOpen) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setFocusedIndex(-1);
      return;
    }

    const firstEnabled = getFirstEnabledIndex();
    if (firstEnabled === -1) return;

    setFocusedIndex(firstEnabled);

    const tryFocus = () => {
      const el = actionRefs.current[firstEnabled];
      if (el) {
        el.focus({ preventScroll: true });
      } else {
        requestAnimationFrame(tryFocus);
      }
    };
    requestAnimationFrame(tryFocus);
  }, [isOpen, getFirstEnabledIndex]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (!isOpen || actionItems.length === 0) return;

      switch (event.key) {
        case "ArrowDown": {
          event.preventDefault();

          let next = (focusedIndex + 1) % actionItems.length;
          let attempts = 0;

          while (attempts < actionItems.length) {
            const action = actionItems[next];
            const disabled =
              typeof action.disabled === "function"
                ? action.disabled(item)
                : action.disabled;

            if (!disabled) break;

            next = (next + 1) % actionItems.length;
            attempts++;
          }

          if (attempts < actionItems.length) {
            setFocusedIndex(next);
            actionRefs.current[next]?.focus({ preventScroll: true });
          }

          break;
        }
        case "ArrowUp": {
          event.preventDefault();

          let next =
            (focusedIndex - 1 + actionItems.length) % actionItems.length;
          let attempts = 0;

          while (attempts < actionItems.length) {
            const action = actionItems[next];
            const disabled =
              typeof action.disabled === "function"
                ? action.disabled(item)
                : action.disabled;

            if (!disabled) break;

            next = (next - 1 + actionItems.length) % actionItems.length;
            attempts++;
          }

          if (attempts < actionItems.length) {
            setFocusedIndex(next);
            actionRefs.current[next]?.focus({ preventScroll: true });
          }

          break;
        }
        case "Enter":
        case " ": {
          event.preventDefault();

          if (focusedIndex >= 0) {
            const action = actionItems[focusedIndex];
            const disabled =
              typeof action.disabled === "function"
                ? action.disabled(item)
                : action.disabled;

            if (!disabled) {
              onSelect(action);
              onClose();
            }
          }

          break;
        }
        case "Tab": {
          event.preventDefault();
          const direction = event.shiftKey ? -1 : 1;
          let nextIndex = (focusedIndex + direction) % actionItems.length;
          if (nextIndex < 0) nextIndex = actionItems.length - 1;

          let attempts = 0;
          while (attempts < actionItems.length) {
            const action = actionItems[nextIndex];
            const disabled =
              typeof action.disabled === "function"
                ? action.disabled(item)
                : action.disabled;
            if (!disabled) break;
            nextIndex = (nextIndex + direction) % actionItems.length;
            if (nextIndex < 0) nextIndex = actionItems.length - 1;
            attempts++;
          }

          if (attempts < actionItems.length) {
            setFocusedIndex(nextIndex);
            actionRefs.current[nextIndex]?.focus({ preventScroll: true });
          }
          break;
        }
        default:
          break;
      }
    },
    [isOpen, actionItems, focusedIndex, item, onSelect, onClose],
  );

  return { focusedIndex, actionRefs, handleKeyDown };
}
