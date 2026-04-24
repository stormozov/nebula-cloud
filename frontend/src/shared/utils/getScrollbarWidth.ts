/**
 * Calculates the width of the browser's vertical scrollbar.
 *
 * This function creates a temporary element with forced scrollbars and measures
 * the difference between its total width (`offsetWidth`) and the inner content
 * width (`clientWidth`), which gives the scrollbar width. The element
 * is immediately removed after measurement.
 *
 * @returns {number} The width of the scrollbar in pixels. Returns `0` if called
 * outside the browser environment.
 *
 * @example
 * const scrollbarWidth = getScrollbarWidth();
 * document.body.style.paddingRight = `${scrollbarWidth}px`;
 */
export function getScrollbarWidth(): number {
  if (typeof window === "undefined") return 0;

  const div = document.createElement("div");
  div.style.overflow = "scroll";
  div.style.width = "100px";
  div.style.height = "100px";

  document.body.append(div);
  const width = div.offsetWidth - div.clientWidth;
  document.body.removeChild(div);

  return width;
}
