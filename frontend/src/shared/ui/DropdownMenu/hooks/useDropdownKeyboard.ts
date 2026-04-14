import { useCallback, useLayoutEffect, useRef, useState } from "react";

import type { IDropdownMenuActionItem } from "../types";

/**
 * Properties for the `useDropdownKeyboard` hook.
 */
interface UseDropdownKeyboardOptions<T> {
  /** Whether the dropdown menu is open */
  isOpen: boolean;
  /** Dropdown menu actions */
  actions: IDropdownMenuActionItem<T>[];
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
  actions,
  item,
  onClose,
  onSelect,
}: UseDropdownKeyboardOptions<T>) {
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const actionRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const getFirstEnabledIndex = useCallback(() => {
    return actions.findIndex((action) => {
      const disabled =
        typeof action.disabled === "function"
          ? action.disabled(item)
          : action.disabled;
      return !disabled;
    });
  }, [actions, item]);

  useLayoutEffect(() => {
    if (!isOpen) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setFocusedIndex(-1);
      return;
    }

    const firstEnabled = getFirstEnabledIndex();
    if (firstEnabled === -1) return; // нет активных пунктов

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
      if (!isOpen) return;

      switch (event.key) {
        case "ArrowDown": {
          event.preventDefault();

          let next = (focusedIndex + 1) % actions.length;
          let attempts = 0;

          while (attempts < actions.length) {
            const action = actions[next];
            const disabled =
              typeof action.disabled === "function"
                ? action.disabled(item)
                : action.disabled;

            if (!disabled) break;

            next = (next + 1) % actions.length;
            attempts++;
          }

          if (attempts < actions.length) {
            setFocusedIndex(next);
            actionRefs.current[next]?.focus({ preventScroll: true });
          }

          break;
        }
        case "ArrowUp": {
          event.preventDefault();

          let next = (focusedIndex - 1 + actions.length) % actions.length;
          let attempts = 0;

          while (attempts < actions.length) {
            const action = actions[next];
            const disabled =
              typeof action.disabled === "function"
                ? action.disabled(item)
                : action.disabled;

            if (!disabled) break;

            next = (next - 1 + actions.length) % actions.length;
            attempts++;
          }

          if (attempts < actions.length) {
            setFocusedIndex(next);
            actionRefs.current[next]?.focus({ preventScroll: true });
          }

          break;
        }
        case "Enter":
        case " ": {
          event.preventDefault();

          if (focusedIndex >= 0) {
            const action = actions[focusedIndex];
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
        default:
          break;
      }
    },
    [isOpen, actions, focusedIndex, item, onSelect, onClose],
  );

  return { focusedIndex, actionRefs, handleKeyDown };
}
