import { useCallback, useEffect, useRef } from "react";

import { getScrollbarWidth } from "../utils";

const activeLocks = new Set<symbol>();
let wasPaddingAdded = false;

/**
 * Custom React hook that conditionally locks scrolling on the document body.
 *
 * Multiple instances of this hook can be active simultaneously. The scroll lock
 * is removed only when all active locks have been released.
 *
 * @param {boolean} isLocked - If `true`, applies scroll lock; if `false`,
 * removes the lock (if no other locks are active).
 */
export const useBodyScrollLock = (isLocked: boolean) => {
  const idRef = useRef(Symbol("scroll-lock"));

  const applyLock = useCallback(() => {
    const hasScroll =
      document.documentElement.scrollHeight > window.innerHeight;

    if (hasScroll) {
      const width = getScrollbarWidth();
      if (width > 0) {
        document.body.style.paddingRight = `${width}px`;
        wasPaddingAdded = true;
      }
    }

    document.body.style.overflow = "hidden";
  }, []);

  const handleRemoveLock = useCallback((id: symbol) => {
    activeLocks.delete(id);

    if (activeLocks.size === 0) {
      // Remove styles only when there's no more locks
      document.body.style.overflow = "";
      if (wasPaddingAdded) {
        document.body.style.paddingRight = "";
        wasPaddingAdded = false;
      }
    }
  }, []);

  useEffect(() => {
    const id = idRef.current;

    if (isLocked) {
      activeLocks.add(id);
      // Apply styles when the page is first blocked
      if (activeLocks.size === 1) applyLock();
    } else {
      if (activeLocks.has(id)) handleRemoveLock(id);
    }

    return () => {
      if (activeLocks.has(id)) handleRemoveLock(id);
    };
  }, [isLocked, handleRemoveLock, applyLock]);
};
