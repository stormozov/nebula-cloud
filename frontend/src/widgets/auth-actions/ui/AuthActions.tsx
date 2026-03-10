import classNames from "classnames";

import { LoginButton, RegisterButton } from "@/features/auth";
import type { ButtonSize } from "@/shared/ui/buttons";

import "./AuthActions.scss";

/**
 * Props for the AuthActions component.
 */
interface IAuthActionsProps {
  registerFirst?: boolean;
  size?: ButtonSize;
  className?: string;
}

/**
 * A component that renders authentication action buttons (Login and Register)
 * with configurable order and size.
 *
 * Button order is controlled via CSS flex-direction, not conditional rendering.
 *
 * @example
 * <AuthActions registerFirst={true} size="large" />
 *
 * @remarks
 * The component uses {@link LoginButton} and {@link RegisterButton} components
 * internally, applying consistent variants:
 * - `LoginButton`: always uses "secondary" variant.
 * - `RegisterButton`: always uses "primary" variant.
 */
export function AuthActions({
  registerFirst = false,
  size = "medium",
  className,
}: IAuthActionsProps) {
  const containerClasses = classNames("auth-actions", {
    "auth-actions--reverse": registerFirst,
    className,
  });

  return (
    <div className={containerClasses}>
      <LoginButton variant="secondary" size={size}>
        Войти
      </LoginButton>
      <RegisterButton variant="primary" size={size}>
        Зарегистрироваться
      </RegisterButton>
    </div>
  );
}
