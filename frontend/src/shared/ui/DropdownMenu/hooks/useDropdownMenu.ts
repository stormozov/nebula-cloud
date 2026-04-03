import { useCallback, useEffect, useRef, useState } from "react";

import { useClickOutside } from "@/shared/hooks/useClickOutside";

/**
 * Properties for the `useDropdownMenu` hook for options props.
 */
interface IUseDropdownMenuOptions {
  isOpenControlled?: boolean;
  closeOnClickOutside?: boolean;
  closeOnEscape?: boolean;
  onOpenChange?: (open: boolean) => void;
}

/**
 * Hook for managing dropdown menu open/close state, click outside, and ESC key.
 */
export function useDropdownMenu(options: IUseDropdownMenuOptions = {}) {
  const {
    isOpenControlled,
    onOpenChange,
    closeOnClickOutside = true,
    closeOnEscape = true,
  } = options;

  const [internalIsOpen, setInternalIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    if (!closeOnEscape) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        e.preventDefault();
        close();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, close, closeOnEscape]);

  useClickOutside(menuRef, () => {
    if (closeOnClickOutside && isOpen) close();
  });

  return { isOpen, setOpen, close, toggle, menuRef };
}
