import type { IUserListResponse } from "@/entities/user";
import { StatusBadge } from "@/shared/ui";

import "./UserListItem.scss";

/**
 * Interface for the props of the UserListItem component.
 */
export interface IUserListItemProps {
  user: IUserListResponse;
  onSelectUser: (userId: number) => void;
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
export function UserListItem({ user, onSelectUser }: IUserListItemProps) {
  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelectUser(user.id);
    }
  };

  return (
    // biome-ignore lint/a11y/useSemanticElements: <It`s need for accessibility>
    <tr
      className="users-list__body-row"
      role="button"
      title={`Открыть информацию о пользователе ${user.username}`}
      aria-label={`Открыть информацию о пользователе ${user.username}`}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      onClick={() => onSelectUser(user.id)}
    >
      <td className="users-list__body-cell">{user.id}</td>
      <td className="users-list__body-cell">{user.username}</td>
      <td className="users-list__body-cell">{user.email}</td>
      <td className="users-list__body-cell">
        <StatusBadge
          isActive={user.isStaff}
          activeText="Да"
          inactiveText="Нет"
          centerX
        />
      </td>
      <td className="users-list__body-cell">
        <StatusBadge isActive={user.isActive} centerX />
      </td>
    </tr>
  );
}
