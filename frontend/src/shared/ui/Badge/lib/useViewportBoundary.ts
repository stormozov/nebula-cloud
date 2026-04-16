import { useLayoutEffect, useState } from "react";

import type { AnchorPosition } from "@/shared/types/common";
import { getAdjustedAnchorPositionTransform } from "@/shared/utils";

const VIEWPORT_PADDING = 4;

/**
 * Custom React hook that calculates and returns a CSS transform string
 * to reposition a badge element when it would otherwise be partially outside
 * the viewport.
 *
 * @param {React.RefObject<HTMLElement | null>} elementRef - Reference to
 * the anchor element (e.g., avatar or icon) that the badge is positioned
 * relative to.
 * @param {AnchorPosition} [position] - Optional position of the badge relative
 * to the anchor element. If not provided, no transformation is applied.
 *
 * @returns {string} A CSS `transform` string
 * (e.g., `translate(calc(-50% + 10px), calc(-50% + 5px))`) to apply to
 * the badge for boundary-safe positioning. Returns an empty string if
 * no adjustment is needed.
 *
 * @example
 * const transform = useViewportBoundary(badgeAnchorRef, "top-right");
 * return <Badge style={{ transform }} />;
 */
export const useViewportBoundary = (
  elementRef: React.RefObject<HTMLElement | null>,
  position?: AnchorPosition,
): string => {
  const [transform, setTransform] = useState<string>("");

  useLayoutEffect(() => {
    if (!position) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setTransform("");
      return;
    }

    const element = elementRef.current;
    if (!element) return;

    const calculateTransform = () => {
      const rect = element.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;

      const newTransform = getAdjustedAnchorPositionTransform({
        position,
        elementRect: rect,
        viewportWidth,
        viewportHeight,
        padding: VIEWPORT_PADDING,
      });

      setTransform(newTransform);
    };

    const observer = new ResizeObserver(() => {
      requestAnimationFrame(calculateTransform);
    });
    observer.observe(element);
    requestAnimationFrame(calculateTransform);

    window.addEventListener("resize", calculateTransform);

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", calculateTransform);
    };
  }, [elementRef, position]);

  return transform;
};
