import type {
  AnchorPosition,
  IAdjustments,
  IPercentageOffsets,
  IVirtualCoordinates,
} from "@/shared/types/common";

/**
 * Parameters required by the `getAdjustedAnchorPositionTransform` function
 * to calculate a boundary-safe CSS transform for positioning a floating element.
 */
export interface IGetAdjustedAnchorPositionTransformParams {
  /** The desired position of the element relative to its anchor. */
  position: AnchorPosition;
  /**
   * The bounding rectangle of the anchor element, obtained
   * via `getBoundingClientRect()`.
   */
  elementRect: DOMRect;
  /** The current width of the browser viewport. */
  viewportWidth: number;
  /** The current height of the browser viewport. */
  viewportHeight: number;
  /**
   * Optional padding buffer (in pixels) from the viewport edges.
   * Ensures the element stays inset within the viewport.
   */
  padding?: number;
}

/**
 * Calculates the base percentage offsets for positioning an element relative
 * to its anchor point.
 *
 * The offsets are used in CSS transforms to align the positioned element.
 *
 * @param position - The desired anchor position (e.g., "top-left").
 *
 * @returns An object containing `baseXPercent` and `baseYPercent`, representing
 * the horizontal and vertical percentage shifts needed for initial alignment.
 */
export const getBasePercentageOffsets = (
  position: AnchorPosition,
): IPercentageOffsets => {
  let baseXPercent = 0;
  let baseYPercent = 0;

  if (position.startsWith("top")) baseYPercent = -50;
  else if (position.startsWith("bottom")) baseYPercent = 50;

  if (position.endsWith("left")) baseXPercent = -50;
  else if (position.endsWith("center")) baseXPercent = -50;
  else if (position.endsWith("right")) baseXPercent = 50;

  return { baseXPercent, baseYPercent };
};

/**
 * Calculates the virtual bounding box of an element after applying base
 * percentage shifts.
 *
 * @param rect - The bounding % of the anchor element (`DOMRect` from
 * `getBoundingClientRect`).
 * @param baseXPercent - The horizontal % shift (e.g., -50 for centering).
 * @param baseYPercent - The vertical % shift (e.g., 50 for bottom alignment).
 *
 * @returns An object with `left`, `right`, `top`, and `bottom` properties
 * representing the virtual edges of the positioned element.
 */
export const calculateVirtualCoordinates = (
  rect: DOMRect,
  baseXPercent: number,
  baseYPercent: number,
): IVirtualCoordinates => {
  const baseShiftX = (rect.width * baseXPercent) / 100;
  const baseShiftY = (rect.height * baseYPercent) / 100;

  return {
    left: rect.left + baseShiftX,
    right: rect.right + baseShiftX,
    top: rect.top + baseShiftY,
    bottom: rect.bottom + baseShiftY,
  };
};

/**
 * Calculates the necessary pixel adjustments to reposition an element
 * so that it remains fully visible within the viewport boundaries.
 *
 * @param virtual - The virtual coordinates of the element after base percentage
 * transforms have been applied. Represents where the element would be without
 * correction.
 * @param viewportWidth - The current width of the browser viewport
 * (usually `window.innerWidth`).
 * @param viewportHeight - The current height of the browser viewport
 * (usually `window.innerHeight`).
 * @param padding - The minimum safe distance (in pixels) that the element must
 * maintain from the viewport edges.
 *
 * @returns An object containing `adjustX` and `adjustY`, representing
 * the horizontal and vertical pixel values needed to adjust the element's
 * position to prevent overflow.
 */
export const calculateViewportAdjustments = (
  virtual: IVirtualCoordinates,
  viewportWidth: number,
  viewportHeight: number,
  padding: number,
): IAdjustments => {
  let adjustX = 0;
  let adjustY = 0;

  if (virtual.left < padding) {
    adjustX = padding - virtual.left;
  } else if (virtual.right > viewportWidth - padding) {
    adjustX = viewportWidth - padding - virtual.right;
  }

  if (virtual.top < padding) {
    adjustY = padding - virtual.top;
  } else if (virtual.bottom > viewportHeight - padding) {
    adjustY = viewportHeight - padding - virtual.bottom;
  }

  return { adjustX, adjustY };
};

/**
 * Generates a CSS `transform` string to position an element relative
 * to an anchor while ensuring it remains fully visible within the viewport.
 *
 * @returns A CSS transform string suitable for the `style.transform` property,
 * combining % and pixel translations to ensure boundary-safe positioning.
 *
 * @example
 * const transform = getAdjustedAnchorPositionTransform({
 *   position: "top-right",
 *   elementRect: element.getBoundingClientRect(),
 *   viewportWidth: window.innerWidth,
 *   viewportHeight: window.innerHeight,
 *   padding: 8,
 * });
 * // Returns: "translate(calc(50% + 0px), calc(-50% + 12px))"
 */
export const getAdjustedAnchorPositionTransform = ({
  position,
  elementRect,
  viewportWidth,
  viewportHeight,
  padding = 4,
}: IGetAdjustedAnchorPositionTransformParams): string => {
  const { baseXPercent, baseYPercent } = getBasePercentageOffsets(position);
  const virtual = calculateVirtualCoordinates(
    elementRect,
    baseXPercent,
    baseYPercent,
  );
  const { adjustX, adjustY } = calculateViewportAdjustments(
    virtual,
    viewportWidth,
    viewportHeight,
    padding,
  );

  const calculatedX = `calc(${baseXPercent}% + ${adjustX}px)`;
  const calculatedY = `calc(${baseYPercent}% + ${adjustY}px)`;
  return `translate(${calculatedX}, ${calculatedY})`;
};
