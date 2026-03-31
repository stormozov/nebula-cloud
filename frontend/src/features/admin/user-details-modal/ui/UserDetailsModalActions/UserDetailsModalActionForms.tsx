import { EditUserForm } from "@/features/admin/edit-user-form";
import { ResetPasswordForm } from "@/features/admin/reset-password-form";

import type { IUserDetailsModalActionsProps } from "../../lib/types";

/**
 * Props type for the `UserActionForms` component, selecting specific properties
 * from `IUserDetailsModalActionsProps` to control form rendering and behavior.
 */
type IUserActionFormsProps = Pick<
  IUserDetailsModalActionsProps,
  "action" | "user" | "onSuccess" | "onClose"
>;

/**
 * Renders the appropriate form based on the specified action.
 */
export function UserDetailsModalActionForms({
  action,
  user,
  onSuccess,
  onClose,
}: IUserActionFormsProps) {
  if (action === "edit") {
    return (
      <EditUserForm user={user} onSuccess={onSuccess} onCancel={onClose} />
    );
  }
  if (action === "reset-password") {
    return (
      <ResetPasswordForm
        userId={user.id}
        onSuccess={onSuccess}
        onCancel={onClose}
      />
    );
  }
  return null;
}
