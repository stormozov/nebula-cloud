import type { ComponentType, SVGProps } from "react";

import type { ICustomIconProps } from "./types";

/**
 * Creates an icon adapter that wraps a raw SVG component with common icon props.
 *
 * @template RawIcon - The React component type for the SVG element, accepting
 * SVGProps.
 * @param {React.ComponentType<React.SVGProps<SVGSVGElement>>} RawIcon - The raw
 * SVG component to be adapted.
 *
 * @example
 * const MyIcon = createIconAdapter(RawMyIcon);
 * <MyIcon size="24px" color="blue" title="My Icon" />
 */
export const createIconAdapter = (
  RawIcon: ComponentType<SVGProps<SVGSVGElement>>,
) => {
  return ({
    size = "1em",
    color = "currentColor",
    className,
    title,
    onClick,
  }: ICustomIconProps) => (
    <RawIcon
      width={size}
      height={size}
      fill={color}
      className={className}
      onClick={onClick}
    >
      {title && <title>{title}</title>}
    </RawIcon>
  );
};
