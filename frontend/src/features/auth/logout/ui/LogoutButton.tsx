import { useNavigate } from "react-router";

import { useLogoutMutation } from "@/entities/user";
import type { IButtonProps } from "@/shared/ui";
import { Button } from "@/shared/ui";

import "./LogoutButton.scss";

/**
 * Logout button component.
 *
 * Calls logout API endpoint and redirects to welcome page.
 *
 * @see {@link Button}
 *
 * @example
 * <LogoutButton variant="ghost" size="small" />
 * <LogoutButton variant="danger">Выйти</LogoutButton>
 */
export function LogoutButton({
  variant = "ghost",
  size = "medium",
  fullWidth = false,
  className,
  children = "Выход",
  ...restProps
}: IButtonProps) {
  const navigate = useNavigate();
  const [logout, { isLoading }] = useLogoutMutation();

  const handleClick = async (): Promise<void> => {
    try {
      await logout().unwrap();
      navigate("/", { replace: true });
    } catch {
      navigate("/", { replace: true });
    }
  };

  return (
    <Button
      type="button"
      variant={variant}
      size={size}
      fullWidth={fullWidth}
      loading={isLoading}
      className={`logout-button ${className || ""}`}
      onClick={handleClick}
      {...restProps}
    >
      {children}
    </Button>
  );
}
