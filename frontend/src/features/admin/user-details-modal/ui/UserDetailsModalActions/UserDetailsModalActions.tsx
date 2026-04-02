import { DeleteUserButton } from "@/features/admin/delete-user-button";
import { ExportUserJson } from "@/features/admin/export-user-json";
import { UserDiskButton } from "@/features/admin/navigate-to-user-disk";
import { ToggleActiveButton } from "@/features/admin/toggle-active-button";
import { ToggleAdminButton } from "@/features/admin/toggle-admin-button";
import { Button, Divider, Heading, PageWrapper } from "@/shared/ui";

import type { IUserDetailsModalActionsProps } from "../../lib/types";
import { UserDetailsModalActionForms } from "./UserDetailsModalActionForms";

import "./UserDetailsModalActions.scss";

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
    onSuccess,
    onClose,
  } = actionProps;

  const isEditAction = action === "edit";
  const isResetPasswordAction = action === "reset-password";
  const isFormVisible = action !== "none";

  return (
    <PageWrapper className="user-details-modal-actions w-full">
      <PageWrapper
        direction="column"
        className="user-details-modal-actions__buttons"
      >
        <Heading level={4} className="user-details-modal-actions__title">
          Действия с аккаунтом
        </Heading>

        {/* Section: Navigate to user disk */}
        <UserDiskButton userId={user.id} isCurrentUser={isCurrentUser} />

        <Divider />

        {/* Section: Main actions */}
        <PageWrapper direction="column" gap={"0.625rem"} fullWidth>
          <Button
            variant={isEditAction ? "primary" : "secondary"}
            icon={{ name: "edit" }}
            onClick={() => setAction("edit")}
            fullWidth
          >
            Редактировать
          </Button>

          <Button
            variant={isResetPasswordAction ? "primary" : "secondary"}
            icon={{ name: "password" }}
            onClick={() => setAction("reset-password")}
            fullWidth
          >
            Сбросить пароль
          </Button>
        </PageWrapper>

        <Divider />

        {/* Section: Export */}
        <ExportUserJson
          userId={user.id}
          buttonProps={{ variant: "secondary", fullWidth: true }}
        />

        <Divider />

        {/* Section: Manage access and dangerous actions */}
        <PageWrapper direction="column" gap={"0.625rem"} fullWidth>
          <ToggleActiveButton
            userId={user.id}
            isActive={user.isActive}
            fullWidth
            disabled={isCurrentUser}
            requestConfirm={requestConfirm}
            onSuccess={() => onSuccess("toggle-active")}
          />

          <ToggleAdminButton
            userId={user.id}
            isStaff={user.isStaff}
            fullWidth
            disabled={isCurrentUser}
            requestConfirm={requestConfirm}
            onSuccess={() => onSuccess("toggle-admin")}
          />

          <DeleteUserButton
            userId={user.id}
            fullWidth
            disabled={isCurrentUser}
            requestConfirm={requestConfirm}
            onSuccess={() => onSuccess("delete", true)}
          />
        </PageWrapper>
      </PageWrapper>

      {isFormVisible && (
        <div className="user-details-modal-actions__area w-full">
          <UserDetailsModalActionForms
            action={action}
            user={user}
            onSuccess={onSuccess}
            onClose={onClose}
          />
        </div>
      )}
    </PageWrapper>
  );
}
