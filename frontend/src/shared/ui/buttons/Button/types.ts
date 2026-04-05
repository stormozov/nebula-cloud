import type { IconName } from "@/shared/ui/Icon";

/**
 * Button variants.
 */
export type ButtonVariant =
  | "primary"
  | "secondary"
  | "danger"
  | "ghost"
  | "outline"
  | "text";

/**
 * Button sizes.
 */
export type ButtonSize = "small" | "medium" | "large";

/**
 * Button component props.
 */
export interface IButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Button ref */
  ref?: React.Ref<HTMLButtonElement>;
  /** Button variant (primary, secondary, danger, ghost, outline, text). */
  variant?: ButtonVariant;
  /** Button size (small, medium, large). */
  size?: ButtonSize;
  /** Button icon config */
  icon?: {
    /** Button icon name */
    name: IconName;
    /** Button icon position */
    isRight?: boolean;
  };
  /** Show loading spinner. */
  loading?: boolean;
  /** Additional CSS class name. */
  className?: string;
  /** Full width button. */
  fullWidth?: boolean;
}
