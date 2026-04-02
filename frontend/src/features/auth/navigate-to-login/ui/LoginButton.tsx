import classNames from "classnames";
import { useNavigate } from "react-router";

import type { IButtonProps } from "@/shared/ui";
import { Button, Icon } from "@/shared/ui";

import "./LoginButton.scss";

/**
 * Navigation button to the login page.
 *
 * Redirects user to `/auth` page when clicked.
 *
 * @see {@link Button}
 *
 * @example
 * <LoginButton variant="primary" size="large" />
 * <LoginButton variant="ghost">Войти</LoginButton>
 */
export function LoginButton({
  variant = "primary",
  size = "medium",
  fullWidth = false,
  className,
  children = "Вход",
  ...restProps
}: IButtonProps) {
  const navigate = useNavigate();

  const handleClick = () => navigate("/auth");

  return (
    <Button
      type="button"
      variant={variant}
      size={size}
      fullWidth={fullWidth}
      className={classNames("login-button", className)}
      onClick={handleClick}
      {...restProps}
    >
      <Icon name="login" />
      {children}
    </Button>
  );
}
