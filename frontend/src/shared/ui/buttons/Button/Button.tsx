import classNames from "classnames";
import type { JSX } from "react";

import type { IButtonProps } from "./types";

import "./Button.scss";

/**
 * Reusable button component with multiple variants and loading state.
 *
 * @param {IButtonProps} props - Component props
 * @param {ButtonVariant} props.variant - Button variant (optional,
 *  default: 'primary')
 * @param {ButtonSize} props.size - Button size (optional, default: 'medium')
 * @param {boolean} props.loading - Show loading spinner (optional)
 * @param {React.ReactNode} props.children - Button content
 * @param {boolean} props.fullWidth - Full width button (optional)
 * @param {string} props.className - Additional CSS class (optional)
 * @param {React.ButtonHTMLAttributes<HTMLButtonElement>} rest - Native button
 *  props
 *
 * @returns {JSX.Element} Button component
 *
 * @example
 * <Button variant="primary" loading={isSubmitting} onClick={handleSubmit}>
 *   Sign In
 * </Button>
 */
export const Button = ({
  variant = "primary",
  size = "medium",
  loading = false,
  children,
  fullWidth = false,
  className,
  disabled,
  ...restProps
}: IButtonProps): JSX.Element => {
  const buttonClasses = classNames("button", {
    [`button--${variant}`]: variant,
    [`button--${size}`]: size,
    "button--loading": loading,
    "button--full-width": fullWidth,
    className,
  });

  return (
    <button
      type="button"
      className={buttonClasses}
      disabled={disabled || loading}
      {...restProps}
    >
      {loading && <span className="button__spinner" aria-hidden="true" />}
      {!loading && <span className="button__content">{children}</span>}
    </button>
  );
};

Button.displayName = "Button";
