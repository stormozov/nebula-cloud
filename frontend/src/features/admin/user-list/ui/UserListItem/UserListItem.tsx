import { memo, useCallback, useState } from "react";

import type { IUserListResponse, UserListItemCopyField } from "@/entities/user";

import { DropdownMenu, type IContextMenuState, StatusBadge } from "@/shared/ui";

import { useUserActions } from "../../lib/useUserActions";

import "./UserListItem.scss";

const initContextMenuState: IContextMenuState = {
  isOpen: false,
  position: { x: 0, y: 0 },
};

/**
 * Interface for the props of the UserListItem component.
 */
export interface IUserListItemProps {
  user: IUserListResponse;
  onSelectUser: (userId: number) => void;
  onCopyField?: (user: IUserListResponse, field: UserListItemCopyField) => void;
}

/**
 * A table row component that displays user information in a list format.
 *
 * @param user - The user object containing the data to display.
 * @returns A JSX element representing a table row with user details.
 *
 * @example
 * <UserListItem user={{
 *    id: 1,
 *    username: 'john_doe',
 *    email: 'john@example.com',
 *    isStaff: true,
 *    isActive: true
 * }} />
 */
export function UserListItem({
  user,
  onSelectUser,
  onCopyField,
}: IUserListItemProps) {
  const [contextMenu, setContextMenu] =
    useState<IContextMenuState>(initContextMenuState);

  const actions = useUserActions({ user, onCopyField });

  const handleRowClick = useCallback(() => {
    onSelectUser(user.id);
  }, [onSelectUser, user.id]);

  const handleContextMenu = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      if (actions.length === 0) return;
      setContextMenu({
        isOpen: true,
        position: { x: e.clientX, y: e.clientY },
      });
    },
    [actions.length],
  );

  const handleContextMenuClose = useCallback(() => {
    setContextMenu((prev) => ({ ...prev, isOpen: false }));
  }, []);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelectUser(user.id);
    }
  };

  return (
    <>
      {/** biome-ignore lint/a11y/useSemanticElements: <tr> */}
      <tr
        className="users-list__body-row"
        role="button"
        title={`Открыть информацию о пользователе ${user.username}`}
        aria-label={`Открыть информацию о пользователе ${user.username}`}
        tabIndex={0}
        onKeyDown={handleKeyDown}
        onClick={handleRowClick}
        onContextMenu={handleContextMenu}
      >
        <td className="users-list__body-cell">{user.id}</td>
        <td className="users-list__body-cell">{user.username}</td>
        <td className="users-list__body-cell">{user.email}</td>
        <td className="users-list__body-cell">
          <StatusBadge isActive={user.isStaff} centerX />
        </td>
        <td className="users-list__body-cell">
          <StatusBadge isActive={user.isActive} centerX />
        </td>
      </tr>
      {actions.length > 0 && (
        <DropdownMenu
          actions={actions}
          item={user}
          position={contextMenu.isOpen ? contextMenu.position : undefined}
          isOpen={contextMenu.isOpen}
          onOpenChange={(open) => !open && handleContextMenuClose()}
          placement="bottom-start"
          closeOnClickOutside
          closeOnEscape
        />
      )}
    </>
  );
}

export const UserListItemMemo = memo(UserListItem);
