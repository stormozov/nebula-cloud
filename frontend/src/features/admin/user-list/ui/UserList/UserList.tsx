import type { IUserListResponse } from "@/entities/user";

import { UserListItem } from "../UserListItem/UserListItem";

import "./UserList.scss";

const USER_LIST_HEADER = ["ID", "Логин", "Email", "Админ", "Активен"];

/**
 * Interface for the props of the UserList component.
 */
interface IUserListProps {
  users: IUserListResponse[] | undefined;
  isLoading: boolean;
  error: string | null | unknown;
  onSelectUser: (userId: number) => void;
}

/**
 * Represents a list of users.
 */
export function UserList({
  users,
  isLoading,
  error,
  onSelectUser,
}: IUserListProps) {
  if (isLoading) return <div className="users-list-loading">Загрузка...</div>;
  if (error) {
    return (
      <div className="users-list-error">Ошибка загрузки пользователей</div>
    );
  }
  if (users?.length === 0) {
    return <div className="users-list-empty">Пользователи не найдены</div>;
  }

  return (
    <div className="users-list">
      <table className="users-list__table">
        <thead className="users-list__header">
          <tr className="users-list__header-row">
            {USER_LIST_HEADER.map((header) => (
              <th key={header} className="users-list__header-cell">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="users-list__body">
          {users?.map((user) => (
            <UserListItem
              key={user.id}
              user={user}
              onSelectUser={onSelectUser}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}
