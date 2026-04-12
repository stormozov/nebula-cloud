import { useNavigate } from "react-router";
import { toast } from "react-toastify";

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
  ...restProps
}: IButtonProps) {
  const navigate = useNavigate();
  const [logout, { isLoading }] = useLogoutMutation();

  const handleClick = async (): Promise<void> => {
    try {
      await logout().unwrap();
      toast.info("Вы вышли из аккаунта", {
        position: "bottom-center",
        autoClose: 2000,
        theme: "light",
      });
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
      icon={{ name: "logout" }}
      fullWidth={fullWidth}
      loading={isLoading}
      className={`logout-button ${className || ""}`}
      onClick={handleClick}
      {...restProps}
    >
      Выход
    </Button>
  );
}
