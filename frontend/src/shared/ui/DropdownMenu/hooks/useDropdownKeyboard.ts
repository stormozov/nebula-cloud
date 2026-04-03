import { useCallback, useEffect, useRef, useState } from "react";

import type { IDropdownMenuActionItem } from "../types";

/**
 * Properties for the `useDropdownKeyboard` hook.
 */
interface UseDropdownKeyboardOptions<T> {
  isOpen: boolean;
  actions: IDropdownMenuActionItem<T>[];
  item: T;
  onClose: () => void;
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

  // Reset focus when menu opens/closes
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => setFocusedIndex(0), 0);
      actionRefs.current[0]?.focus();
    } else {
      setTimeout(() => setFocusedIndex(-1), 0);
    }
  }, [isOpen]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (!isOpen) return;

      switch (event.key) {
        case "ArrowDown":
          event.preventDefault();
          setFocusedIndex((prev) => {
            const next = (prev + 1) % actions.length;
            actionRefs.current[next]?.focus();
            return next;
          });
          break;
        case "ArrowUp":
          event.preventDefault();
          setFocusedIndex((prev) => {
            const next = (prev - 1 + actions.length) % actions.length;
            actionRefs.current[next]?.focus();
            return next;
          });
          break;
        case "Enter":
        case " ":
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
        default:
          break;
      }
    },
    [isOpen, actions, focusedIndex, item, onSelect, onClose],
  );

  return { focusedIndex, actionRefs, handleKeyDown };
}
