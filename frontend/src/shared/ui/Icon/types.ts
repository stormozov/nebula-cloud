import type { SVGProps } from "react";

/**
 * Represents the customizable properties for an icon component.
 *
 * This interface defines the common set of props used by adapted icon components
 * to standardize their API, allowing control over appearance and behavior.
 */
export interface ICustomIconProps {
  /** The size of the icon. Can be a number or a string CSS length. */
  size?: number | string;
  /** The fill color of the icon. Accepts any valid CSS color value. */
  color?: string;
  /** Additional CSS class names to apply to the icon element. */
  className?: string;
  /**
   * Accessible title for the icon. If provided, it will be rendered as
   * a `<title>` element inside the SVG. Used for accessibility and SEO purposes.
   */
  title?: string;
  /**
   * Click event handler for the icon. Triggered when the icon is clicked.
   * Matches the onClick handler type from SVGProps<SVGSVGElement>.
   */
  onClick?: SVGProps<SVGSVGElement>["onClick"];
}
