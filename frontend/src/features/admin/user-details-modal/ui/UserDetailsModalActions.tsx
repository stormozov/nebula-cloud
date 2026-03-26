import classNames from "classnames";

import { EditUserForm } from "@/features/admin/edit-user-form";
import { ResetPasswordForm } from "@/features/admin/reset-password-form";
import { ToggleActiveButton } from "@/features/admin/toggle-active-button";
import { ToggleAdminButton } from "@/features/admin/toggle-admin-button";
import { Button, Divider, Heading, Icon, PageWrapper } from "@/shared/ui";

import { DeleteUserButton } from "../../delete-user-button";
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
    isCurrentUser,
    setAction,
    requestConfirm,
    onClose,
    editFormSuccess,
    resetPasswordFormSuccess,
    toggleActiveSuccess,
    toggleAdminSuccess,
    deleteUserSuccess,
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
            <Icon name="edit" />
            Редактировать
          </Button>

          <Button
            variant={isResetPasswordAction ? "primary" : "secondary"}
            fullWidth
            onClick={() => setAction("reset-password")}
          >
            <Icon name="password" />
            Сбросить пароль
          </Button>

          <Divider gap="0.625rem" />

          <ToggleActiveButton
            userId={user.id}
            isActive={user.isActive}
            fullWidth
            disabled={isCurrentUser}
            requestConfirm={requestConfirm}
            onSuccess={toggleActiveSuccess}
          />

          <ToggleAdminButton
            userId={user.id}
            isStaff={user.isStaff}
            fullWidth
            disabled={isCurrentUser}
            requestConfirm={requestConfirm}
            onSuccess={toggleAdminSuccess}
          />

          <DeleteUserButton
            userId={user.id}
            fullWidth
            disabled={isCurrentUser}
            requestConfirm={requestConfirm}
            onSuccess={deleteUserSuccess}
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
