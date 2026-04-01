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
  /**
   * Button variant (primary, secondary, danger, ghost, outline, text).
   */
  variant?: ButtonVariant;
  /**
   * Button size (small, medium, large).
   */
  size?: ButtonSize;
  /**
   * Show loading spinner.
   */
  loading?: boolean;
  /**
   * Additional CSS class name.
   */
  className?: string;
  /**
   * Full width button.
   */
  fullWidth?: boolean;
}
