import type { IUserListResponse, UserListItemCopyField } from "@/entities/user";
import { useNavigateToUserDisk } from "@/shared/hooks";
import type { IDropdownMenuActionItem } from "@/shared/ui";

/**
 * Props for the `useUserActions` hook.
 */
export interface UseUserActionsProps {
  /** The user to generate actions for. */
  user: IUserListResponse;
  /** Optional callback to handle copying a user field. */
  onCopyField?: (user: IUserListResponse, field: UserListItemCopyField) => void;
}

/**
 * Generates action items for a user to be used in DropdownMenu (context menu).
 */
export const useUserActions = ({
  user,
  onCopyField,
}: UseUserActionsProps): IDropdownMenuActionItem<IUserListResponse>[] => {
  const { navigateToDisk } = useNavigateToUserDisk({ userId: user.id });

  const actions: IDropdownMenuActionItem<IUserListResponse>[] = [];

  if (onCopyField) {
    actions.push({
      id: "go-to-folder",
      label: `Перейти к диску`,
      icon: "folder",
      onClick: () => navigateToDisk(),
    });
    actions.push({
      id: "copy-id",
      label: `Копировать ID`,
      icon: "copy",
      onClick: () => onCopyField(user, "id"),
    });
    actions.push({
      id: "copy-username",
      label: `Копировать логин`,
      icon: "copy",
      onClick: () => onCopyField(user, "username"),
    });
    actions.push({
      id: "copy-email",
      label: `Копировать email`,
      icon: "copy",
      onClick: () => onCopyField(user, "email"),
    });
  }

  return actions;
};
