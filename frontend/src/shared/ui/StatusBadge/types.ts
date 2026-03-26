import type { IconColor, IconName } from "../Icon";

/**
 * Represents the available variants for a status badge.
 */
export type StatusBadgeVariant = "success" | "error";

/**
 * Represents the possible states of a status indicator.
 */
export type StatusState = "active" | "inactive";

/**
 * Configuration object defining the icon and color for a specific status
 * appearance.
 */
export interface StatusIconConfig {
  icon: IconName;
  color: IconColor;
}

/**
 * Defines the configuration for both active and inactive states of a status
 * variant.
 */
export interface StatusVariantConfig {
  active: StatusIconConfig;
  inactive: StatusIconConfig;
}

/**
 * A mapping of status badge variants to their respective configurations for
 * active and inactive states. Each key corresponds to
 * a {@link StatusBadgeVariant}, and maps to a {@link StatusVariantConfig}.
 */
export type StatusConfig = Record<StatusBadgeVariant, StatusVariantConfig>;

/**
 * Constant configuration object that defines the visual representation
 * (icon and color) of status badges based on their variant
 * ("success" or "error") and state ("active" or "inactive").
 *
 * This object is frozen with `as const` to ensure immutability and precise
 * literal typing.
 *
 * @example
 * ```ts
 * STATUS_CONFIG.success.active; // { icon: 'check', color: 'success' }
 * STATUS_CONFIG.error.inactive; // { icon: 'check', color: 'success' }
 * ```
 */
export const STATUS_CONFIG: StatusConfig = {
  success: {
    active: { icon: "check", color: "success" },
    inactive: { icon: "close", color: "error" },
  },
  error: {
    active: { icon: "close", color: "error" },
    inactive: { icon: "check", color: "success" },
  },
} as const;

/**
 * Props interface for the StatusBadge component.
 */
export interface StatusBadgeProps {
  /** * Determines whether the status is currently active. */
  isActive: boolean;
  /** Optional text to display when the status is active. */
  activeText?: string;
  /** Optional text to display when the status is inactive. */
  inactiveText?: string;
  /** Defines the visual variant of the status badge. */
  variant?: StatusBadgeVariant;
  /**
   * When set to true, centers the content of the badge horizontally using CSS.
   */
  centerX?: boolean;
  /**
   * When set to true, renders only the icon without any accompanying text.
   *
   * Useful for compact representations where space is limited.
   */
  iconOnly?: boolean;
  /** Additional CSS class name(s) to apply to the root element of the badge. */
  className?: string;
}
