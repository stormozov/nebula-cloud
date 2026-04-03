import { type RefObject, useLayoutEffect, useState } from "react";

import type { DropdownMenuActionItemPlacement } from "../types";

/**
 * Properties for the `useDropdownPositioning` hook.
 */
interface UseDropdownPositioningOptions {
  isOpen: boolean;
  triggerRef: RefObject<HTMLElement | null>;
  menuRef: RefObject<HTMLElement | null>;
  position?: { x: number; y: number };
  placement?: DropdownMenuActionItemPlacement;
}

/**
 * Hook that calculates CSS position for a dropdown menu.
 *
 * Supports positioning relative to a trigger element or absolute coordinates
 * (context menu). Automatically adjusts position to keep menu within viewport.
 */
export function useDropdownPositioning({
  isOpen,
  triggerRef,
  menuRef,
  position,
  placement = "bottom-start",
}: UseDropdownPositioningOptions) {
  const [menuStyle, setMenuStyle] = useState<React.CSSProperties>({
    opacity: 0,
  });

  useLayoutEffect(() => {
    if (!isOpen) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMenuStyle({ opacity: 0 });
      return;
    }

    if (position) {
      setMenuStyle({
        position: "fixed",
        left: position.x,
        top: position.y,
        opacity: 0,
      });
    }

    let rafId: number;
    let resizeObserver: ResizeObserver | null = null;

    const computePosition = (menuWidth: number, menuHeight: number) => {
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;
      const margin = 8;

      if (position) {
        let left = position.x;
        let top = position.y;

        // Horizontal correction
        if (left + menuWidth > viewportWidth)
          left = viewportWidth - menuWidth - margin;
        if (left < margin) left = margin;

        // Vertical correction
        if (top + menuHeight > viewportHeight)
          top = viewportHeight - menuHeight - margin;
        if (top < margin) top = margin;

        setMenuStyle({
          position: "fixed",
          left,
          top,
          opacity: 1,
          transition: "opacity 0.2s ease",
        });
        return;
      }

      // Positioning relative to trigger
      if (triggerRef.current) {
        const rect = triggerRef.current.getBoundingClientRect();
        const { top, left, width, height } = rect;

        let topPos = 0;
        let leftPos = 0;

        switch (placement) {
          case "bottom-start":
            topPos = top + height;
            leftPos = left;
            break;
          case "bottom-end":
            topPos = top + height;
            leftPos = left + width - menuWidth;
            break;
          case "top-start":
            topPos = top - menuHeight;
            leftPos = left;
            break;
          case "top-end":
            topPos = top - menuHeight;
            leftPos = left + width - menuWidth;
            break;
          default:
            topPos = top + height;
            leftPos = left;
        }

        // Horizontal correction
        if (leftPos + menuWidth > viewportWidth) {
          const alternativeLeft = left + width - menuWidth;
          if (alternativeLeft >= margin) leftPos = alternativeLeft;
          else leftPos = Math.max(margin, viewportWidth - menuWidth - margin);
        }
        if (leftPos < margin) leftPos = margin;

        // Vertical correction
        let actualTop = topPos;
        let actualPlacement = placement;
        if (
          placement.startsWith("bottom") &&
          topPos + menuHeight > viewportHeight
        ) {
          const alternativeTop = top - menuHeight;
          if (alternativeTop >= margin) {
            actualTop = alternativeTop;
            actualPlacement = "top-start";
          } else {
            actualTop = Math.max(margin, viewportHeight - menuHeight - margin);
          }
        } else if (placement.startsWith("top") && topPos - menuHeight < 0) {
          const alternativeTop = top + height;
          if (alternativeTop + menuHeight <= viewportHeight) {
            actualTop = alternativeTop;
            actualPlacement = "bottom-start";
          } else {
            actualTop = Math.max(margin, viewportHeight - menuHeight - margin);
          }
        } else if (topPos < margin) {
          actualTop = margin;
        } else if (topPos + menuHeight > viewportHeight) {
          actualTop = viewportHeight - menuHeight - margin;
        }

        // If the placement has changed, recalculate the horizontal
        let actualLeft = leftPos;
        if (actualPlacement !== placement) {
          if (
            actualPlacement === "bottom-end" ||
            actualPlacement === "top-end"
          ) {
            actualLeft = left + width - menuWidth;
          } else {
            actualLeft = left;
          }
          if (actualLeft + menuWidth > viewportWidth)
            actualLeft = Math.max(margin, viewportWidth - menuWidth - margin);
          if (actualLeft < margin) actualLeft = margin;
        }

        setMenuStyle({
          position: "fixed",
          top: actualTop,
          left: actualLeft,
          opacity: 1,
          transition: "opacity 0.2s ease",
        });
      }
    };

    const tryCompute = () => {
      if (menuRef.current) {
        const menuWidth = menuRef.current.offsetWidth;
        const menuHeight = menuRef.current.offsetHeight;
        if (menuWidth > 0 && menuHeight > 0) {
          computePosition(menuWidth, menuHeight);
          return;
        }
      }
      rafId = requestAnimationFrame(tryCompute);
    };

    tryCompute();

    if (menuRef.current) {
      resizeObserver = new ResizeObserver(() => {
        if (isOpen) tryCompute();
      });
      resizeObserver.observe(menuRef.current);
    }

    const handleWindowChange = () => {
      if (isOpen) tryCompute();
    };
    window.addEventListener("resize", handleWindowChange);
    window.addEventListener("scroll", handleWindowChange);

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      if (resizeObserver) resizeObserver.disconnect();
      window.removeEventListener("resize", handleWindowChange);
      window.removeEventListener("scroll", handleWindowChange);
    };
  }, [isOpen, position, placement, triggerRef, menuRef]);

  return { menuStyle };
}
