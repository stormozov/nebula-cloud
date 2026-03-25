import classNames from "classnames";
import { MdEdit } from "react-icons/md";
import { PiPasswordBold } from "react-icons/pi";

import { EditUserForm } from "@/features/admin/edit-user-form";
import { ResetPasswordForm } from "@/features/admin/reset-password-form";
import { ToggleActiveButton } from "@/features/admin/toggle-active-button";
import { Button, Divider, Heading, PageWrapper } from "@/shared/ui";

import type { IUserDetailsModalActionsProps } from "../lib/types";

/**
 * Props interface for the UserDetailsModalActions component.
 */
export interface IUserDetailsModalActionsComponentProps {
  actionProps: IUserDetailsModalActionsProps;
}

/**
 * Component that manages and renders the action controls in the user details
 * modal.
 */
export function UserDetailsModalActions({
  actionProps,
}: IUserDetailsModalActionsComponentProps) {
  const {
    user,
    action,
    setAction,
    onClose,
    editFormSuccess,
    resetPasswordFormSuccess,
    toggleActiveSuccess,
  } = actionProps;

  const isEditAction = action === "edit";
  const isResetPasswordAction = action === "reset-password";

  return (
    <PageWrapper className="user-details-modal__actions">
      <PageWrapper
        direction="column"
        className="user-details-modal__actions-buttons"
      >
        <Heading level={4} className="user-details-modal__actions-title">
          Действия с аккаунтом
        </Heading>

        <PageWrapper direction="column" gap={"0.625rem"} fullWidth>
          <Button
            variant={isEditAction ? "primary" : "secondary"}
            fullWidth
            onClick={() => setAction("edit")}
          >
            <MdEdit />
            Редактировать
          </Button>

          <Button
            variant={isResetPasswordAction ? "primary" : "secondary"}
            fullWidth
            onClick={() => setAction("reset-password")}
          >
            <PiPasswordBold />
            Сбросить пароль
          </Button>

          <Divider gap="0.625rem" />

          <ToggleActiveButton
            userId={user.id}
            isActive={user.isActive}
            fullWidth
            onSuccess={toggleActiveSuccess}
          />
        </PageWrapper>
      </PageWrapper>

      <div
        className={classNames("user-details-modal__actions-area", {
          active: action !== "none",
        })}
      >
        {isEditAction && (
          <EditUserForm
            user={user}
            onSuccess={editFormSuccess}
            onCancel={onClose}
          />
        )}
        {isResetPasswordAction && (
          <ResetPasswordForm
            userId={user.id}
            onSuccess={resetPasswordFormSuccess}
            onCancel={onClose}
          />
        )}
      </div>
    </PageWrapper>
  );
}
