/**
 * Anchor position variants.
 */
export type AnchorPosition =
  | "top-left"
  | "top-center"
  | "top-right"
  | "bottom-left"
  | "bottom-center"
  | "bottom-right";

/**
 * Represents the adjustment values in pixels needed to reposition an element
 * to keep it within the viewport boundaries.
 */
export interface IAdjustments {
  /** Horizontal adjustment in pixels. */
  adjustX: number;
  /** Vertical adjustment in pixels. */
  adjustY: number;
}

/**
 * Represents the base offset percentages used to position an element relative
 * to its anchor point (e.g., -50% for centering).
 */
export interface IPercentageOffsets {
  /**
   * The horizontal offset percentage applied to align the element
   * along the X-axis (e.g., -50% to center horizontally).
   */
  baseXPercent: number;
  /**
   * The vertical offset percentage applied to align the element
   * along the Y-axis (e.g., -50% to center vertically).
   */
  baseYPercent: number;
}

/**
 * Represents the virtual bounding box coordinates of an element after applying
 * base percentage offsets. Used to determine if the element overflows
 * the viewport.
 */
export interface IVirtualCoordinates {
  /** The calculated left edge of the element after base transformation. */
  left: number;
  /** The calculated right edge of the element after base transformation. */
  right: number;
  /** The calculated top edge of the element after base transformation. */
  top: number;
  /** The calculated bottom edge of the element after base transformation. */
  bottom: number;
}
