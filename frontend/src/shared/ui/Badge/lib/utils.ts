import type React from "react";

/**
 * Determines whether a badge should be hidden based on its content and props.
 *
 * The badge is hidden if:
 * - It's not in dot mode (`dot` is false).
 * - The `children` content is `null` or `undefined`.
 * - The numeric content is `0` and `showZero` is `false`.
 * - The string content parses as a number equal to `0` and `showZero` is `false`.
 *
 * @param children - The content of the badge (e.g., number, string, or React
 * node).
 * @param showZero - If `true`, the badge will be shown even when the value
 * is zero.
 * @param dot - If `true`, the badge is in dot mode and should never be hidden
 * based on content.
 *
 * @returns `true` if the badge should be hidden; otherwise, `false`.
 *
 * @example
 * shouldHideBadge(0, false, false); // true
 * shouldHideBadge(0, true, false);  // false
 * shouldHideBadge(null, false, false); // true
 * shouldHideBadge(5, false, false); // false
 * shouldHideBadge(0, false, true);  // false (dot badges are never hidden)
 */
export const shouldHideBadge = (
  children: React.ReactNode,
  showZero: boolean,
  dot: boolean,
): boolean => {
  if (dot) return false;
  if (children === undefined || children === null) return true;
  if (typeof children === "number") return children === 0 && !showZero;
  if (typeof children === "string") {
    const num = Number(children);
    return !Number.isNaN(num) && num === 0 && !showZero;
  }
  return false;
};

/**
 * Formats the display content of a badge, optionally applying a maximum count
 * limit.
 *
 * @param children - The content of the badge to format.
 * @param maxCount - Optional upper limit for numeric values. If exceeded,
 * displays `${maxCount}+`.
 * @param dot - If `true`, indicates the badge is in dot mode and should not
 * display any text.
 *
 * @returns Formatted content for display — either the original content,
 * `${maxCount}+`, or `null`.
 *
 * @example
 * formatDisplayContent(10, 9);     // "9+"
 * formatDisplayContent("15", 9);   // "9+"
 * formatDisplayContent(5, 9);      // 5
 * formatDisplayContent(5, 9, true); // null
 * formatDisplayContent("New", 5);  // "New"
 */
export const formatDisplayContent = (
  children: React.ReactNode,
  maxCount?: number,
  dot?: boolean,
): React.ReactNode => {
  if (dot) return null;
  if (
    typeof children === "number" &&
    maxCount !== undefined &&
    children > maxCount
  ) {
    return `${maxCount}+`;
  }
  if (typeof children === "string") {
    const num = Number(children);
    if (!Number.isNaN(num) && maxCount !== undefined && num > maxCount) {
      return `${maxCount}+`;
    }
  }
  return children;
};
