import classNames from "classnames";

import { Icon } from "@/shared/ui/Icon";

import {
  STATUS_CONFIG,
  type StatusBadgeProps,
  type StatusState,
} from "./types";

import "./StatusBadge.scss";

/**
 * A presentational component that renders a status badge with an icon and
 * optional text, indicating the current state (active/inactive) using visual
 * styling based on variant.
 *
 * The appearance is determined by the `isActive` state and `variant` prop,
 * which together select the appropriate icon and color from
 * the {@link STATUS_CONFIG} map.
 *
 * @example
 * ```tsx
 * <StatusBadge
 *    isActive={true}
 *    variant="error"
 *    activeText="Connected"
 *    inactiveText="Disconnected"
 * />
 * ```
 */
export function StatusBadge({
  isActive,
  activeText = "Да",
  inactiveText = "Нет",
  variant = "success",
  centerX = false,
  iconOnly = false,
  className = "",
}: StatusBadgeProps) {
  const state: StatusState = isActive ? "active" : "inactive";
  const config = STATUS_CONFIG[variant][state];

  const text = isActive ? activeText : inactiveText;
  const classes = classNames(
    "status-badge",
    `status-badge--${variant}`,
    {
      "center-x": centerX,
      "icon-only": iconOnly,
    },
    className,
  );

  return (
    // biome-ignore lint/a11y/useSemanticElements: <>
    <div className={classes} role="status" aria-label={text}>
      <Icon name={config.icon} color={config.color} aria-hidden="true" />

      {!iconOnly && text && (
        <span
          className="status-badge__text"
          style={{
            color:
              config.color === "success"
                ? "var(--color-success)"
                : "var(--color-error)",
          }}
        >
          {text}
        </span>
      )}
    </div>
  );
}
