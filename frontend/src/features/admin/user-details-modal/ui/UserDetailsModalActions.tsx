import classNames from "classnames";
import { MdEdit } from "react-icons/md";

import { EditUserForm } from "@/features/admin/edit-user-form";
import { Button, PageWrapper } from "@/shared/ui";

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
  const { user, action, setAction, onClose, editFormSuccess } = actionProps;

  return (
    <div className="user-details-modal__actions">
      <PageWrapper className="user-details-modal__actions-buttons">
        <Button
          variant={action === "edit" ? "primary" : "secondary"}
          fullWidth
          onClick={() => setAction("edit")}
        >
          <MdEdit />
          Редактировать
        </Button>
      </PageWrapper>

      <div
        className={classNames("user-details-modal__actions-area", {
          active: action !== "none",
        })}
      >
        {action === "edit" && (
          <EditUserForm
            user={user}
            onSuccess={editFormSuccess}
            onCancel={onClose}
          />
        )}
      </div>
    </div>
  );
}
