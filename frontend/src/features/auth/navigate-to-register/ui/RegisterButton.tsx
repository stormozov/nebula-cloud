import classNames from "classnames";
import { useNavigate } from "react-router";

import type { IButtonProps } from "@/shared/ui";
import { Button } from "@/shared/ui";

import "./RegisterButton.scss";

/**
 * Navigation button to the registration page.
 *
 * Redirects user to `/auth?tab=register` page when clicked.
 *
 * @see {@link Button}
 *
 * @example
 * <RegisterButton variant="primary" size="large" />
 * <RegisterButton variant="secondary">Создать аккаунт</RegisterButton>
 */
export function RegisterButton({
  variant = "primary",
  size = "medium",
  fullWidth = false,
  className,
  children = "Регистрация",
  ...restProps
}: IButtonProps) {
  const navigate = useNavigate();

  const handleClick = () => navigate("/auth?tab=register");

  return (
    <Button
      type="button"
      variant={variant}
      size={size}
      fullWidth={fullWidth}
      className={classNames("register-button", className)}
      onClick={handleClick}
      {...restProps}
    >
      {children}
    </Button>
  );
}
