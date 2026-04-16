import classNames from "classnames";

import { Icon } from "../../Icon";
import type { IButtonProps } from "./types";

import "./Button.scss";

/**
 * Reusable button component with multiple variants and loading state.
 *
 * @example
 * <Button variant="primary" loading={isSubmitting} onClick={handleSubmit}>
 *   Sign In
 * </Button>
 */
export const Button = ({
  children,
  variant = "primary",
  size = "medium",
  loading = false,
  fullWidth = false,
  icon,
  className,
  disabled,
  ...restProps
}: IButtonProps) => {
  const buttonClasses = classNames(
    "button",
    {
      [`button--${variant}`]: variant,
      [`button--${size}`]: size,
      "button--loading": loading,
      "w-full": fullWidth,
      "button--icon-right": icon?.isRight,
    },
    className,
  );

  return (
    <button
      type="button"
      className={buttonClasses}
      disabled={disabled || loading}
      {...restProps}
    >
      {loading && <span className="button__spinner" aria-hidden="true" />}
      {!loading && icon && <Icon name={icon.name} className="button__icon" />}
      {!loading && children}
    </button>
  );
};

Button.displayName = "Button";
