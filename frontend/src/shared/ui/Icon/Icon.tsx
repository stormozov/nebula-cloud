import React from "react";

import { ICONS } from "./iconsRegistry";

// =============================================================================
// UTILS
// =============================================================================

export type IconName = keyof typeof ICONS;

export type IconColor =
  | "currentColor"
  | "text-primary"
  | "text-secondary"
  | "text-tertiary"
  | "primary"
  | "success"
  | "warning"
  | "error"
  | "info"
  | (string & {});

const colorMap: Record<Exclude<IconColor, "currentColor">, string> = {
  "text-primary": "var(--color-text-primary)",
  "text-secondary": "var(--color-text-secondary)",
  "text-tertiary": "var(--color-text-tertiary)",
  "text-inverse": "var(--color-text-inverse)",
  primary: "var(--color-primary)",
  success: "var(--color-success)",
  warning: "var(--color-warning)",
  error: "var(--color-error)",
  info: "var(--color-info)",
};

/**
 * Interface for Icon component props.
 */
interface IconProps {
  name: IconName;
  size?: number | string;
  color?: IconColor;
  className?: string;
  title?: string;
  onClick?: React.MouseEventHandler<SVGElement>;
}

// =============================================================================
// COMPONENT
// =============================================================================

/**
 * A memoized React component for rendering icons based on a name key.
 *
 * This component dynamically renders an icon from the `ICONS` registry using
 * the provided `name`. It supports customizable size, color, className, title,
 * and click handler. The component is wrapped with `React.memo` to prevent
 * unnecessary re-renders when props are unchanged.
 *
 * @example
 * <Icon name="check" size={24} color="green" />
 *
 * @example
 * <Icon name="close" /> // Renders the close icon with default settings
 *
 * @remarks
 * - If the provided `name` does not exist in `ICONS`, the component returns
 * `null`.
 * - The `color` prop first checks a `colorMap` for predefined colors;
 * if not found, uses the provided string as-is.
 * - The `size` prop passes `undefined` when "currentSize" is used, allowing
 * the icon to inherit text size.
 */
export const Icon = React.memo<IconProps>(function Icon({
  name,
  size = "currentSize",
  color = "currentColor",
  className = "",
  title,
  onClick,
}) {
  const IconComponent = ICONS[name];
  if (!IconComponent) return null;

  const resolvedColor =
    color === "currentColor"
      ? "currentColor"
      : (colorMap[color as keyof typeof colorMap] ?? color);

  const resolvedSize = size === "currentSize" ? undefined : size;

  return (
    <IconComponent
      size={resolvedSize}
      color={resolvedColor}
      className={className}
      title={title}
      onClick={onClick}
    />
  );
});
