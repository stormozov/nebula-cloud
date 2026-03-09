/**
 * Button variants.
 */
export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

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
   * Button variant (primary, secondary, danger, ghost).
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
   * Button children (text or icon).
   */
  children: React.ReactNode;
  /**
   * Additional CSS class name.
   */
  className?: string;
  /**
   * Full width button.
   */
  fullWidth?: boolean;
}
