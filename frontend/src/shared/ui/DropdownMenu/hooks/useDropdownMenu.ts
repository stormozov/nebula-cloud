import { useCallback, useEffect, useRef, useState } from "react";

import { useClickOutside } from "@/shared/hooks/useClickOutside";

/**
 * Props interface for the `useDropdownMenu` hook.
 */
interface IUseDropdownMenuProps {
  /** Determines whether the dropdown is open or closed. */
  isOpenControlled?: boolean;
  /** Determines whether the dropdown should close when clicking outside. */
  closeOnClickOutside?: boolean;
  /** Determines whether the dropdown should close when pressing the ESC key. */
  closeOnEscape?: boolean;
  /** Callback function to update the open state of the dropdown. */
  onOpenChange?: (open: boolean) => void;
}

/**
 * Return type of the `useDropdownMenu` hook.
 */
interface IUseDropdownMenuReturns {
  /** Current open/closed state of the dropdown menu. */
  isOpen: boolean;
  /** Reference to the dropdown menu element (container). */
  menuRef: React.RefObject<HTMLDivElement | null>;
  /** Function to programmatically set the open state of the dropdown. */
  setOpen: (open: boolean) => void;
  /** Toggles the dropdown between open and closed states. */
  toggle: () => void;
  /** Closes the dropdown menu. */
  close: () => void;
  /** Closes the dropdown and restores focus to the previously focused element */
  closeAndRestoreFocus: () => void;
}

/**
 * Hook for managing dropdown menu open/close state, click outside, and ESC key.
 */
export function useDropdownMenu(
  props: IUseDropdownMenuProps = {},
): IUseDropdownMenuReturns {
  const {
    isOpenControlled,
    onOpenChange,
    closeOnClickOutside = true,
    closeOnEscape = true,
  } = props;

  const [internalIsOpen, setInternalIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  const isOpen =
    isOpenControlled !== undefined ? isOpenControlled : internalIsOpen;

  const setOpen = useCallback(
    (open: boolean) => {
      if (isOpenControlled === undefined) setInternalIsOpen(open);
      onOpenChange?.(open);
    },
    [isOpenControlled, onOpenChange],
  );

  const close = useCallback(() => setOpen(false), [setOpen]);
  const toggle = useCallback(() => setOpen(!isOpen), [setOpen, isOpen]);

  const closeAndRestoreFocus = useCallback(() => {
    close();
    setTimeout(() => triggerRef.current?.focus(), 0);
  }, [close]);

  useEffect(() => {
    if (isOpen) {
      triggerRef.current = document.activeElement as HTMLElement | null;
    }
  }, [isOpen]);

  useEffect(() => {
    if (!closeOnEscape) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;

      if (e.key === "Escape") {
        e.preventDefault();
        closeAndRestoreFocus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, closeOnEscape, closeAndRestoreFocus]);

  useClickOutside(menuRef, () => {
    if (closeOnClickOutside && isOpen) {
      close();
      setTimeout(() => {
        triggerRef.current?.focus();
      }, 0);
    }
  });

  return { isOpen, menuRef, setOpen, close, toggle, closeAndRestoreFocus };
}
