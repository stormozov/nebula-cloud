import type { IButtonProps } from "@/shared/ui";
import { Button } from "@/shared/ui";

import { useLogout } from "../lib/useLogout";

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
  ...restProps
}: IButtonProps) {
  const { logout, isLoading } = useLogout();

  return (
    <Button
      type="button"
      variant={variant}
      size={size}
      icon={{ name: "logout" }}
      fullWidth={fullWidth}
      loading={isLoading}
      className={`logout-button ${className || ""}`}
      onClick={logout}
      {...restProps}
    >
      Выход
    </Button>
  );
}
