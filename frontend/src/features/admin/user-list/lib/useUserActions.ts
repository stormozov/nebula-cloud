import { useCallback, useMemo } from "react";

import type { IUserListResponse, UserListItemCopyField } from "@/entities/user";
import { useNavigateToUserDisk } from "@/shared/hooks";
import type { DropdownMenuItem } from "@/shared/ui";

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
}: UseUserActionsProps): DropdownMenuItem<IUserListResponse>[] => {
  const { navigateToDisk } = useNavigateToUserDisk({ userId: user.id });

  const addSeparator = useCallback(
    (items: DropdownMenuItem<IUserListResponse>[]) => {
      if (items.length > 0) items.push({ type: "separator" });
    },
    [],
  );

  const actions = useMemo(() => {
    const items: DropdownMenuItem<IUserListResponse>[] = [];

    items.push({
      id: "go-to-folder",
      label: `Перейти к диску`,
      icon: "folder",
      onClick: () => navigateToDisk(),
    });

    if (onCopyField) {
      addSeparator(items);
      items.push({
        id: "copy-id",
        label: `Копировать ID`,
        icon: "copy",
        onClick: () => onCopyField(user, "id"),
      });
      items.push({
        id: "copy-username",
        label: `Копировать логин`,
        icon: "copy",
        onClick: () => onCopyField(user, "username"),
      });
      items.push({
        id: "copy-email",
        label: `Копировать email`,
        icon: "copy",
        onClick: () => onCopyField(user, "email"),
      });
    }

    return items;
  }, [navigateToDisk, onCopyField, addSeparator, user]);

  return actions;
};
