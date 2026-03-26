import { useGetUsersQuery } from "@/entities/user";
import { UserListItem } from "../UserListItem/UserListItem";

import "./UserList.scss";

const USER_LIST_HEADER = ["ID", "Логин", "Email", "Админ", "Активен"];

interface IUserListProps {
  onSelectUser: (userId: number) => void;
}

/**
 * Represents a list of users.
 */
export const UserList = ({ onSelectUser }: IUserListProps) => {
  const { data: users, isLoading, error } = useGetUsersQuery();

  if (isLoading) return <div className="user-list-loading">Загрузка...</div>;
  if (error) {
    return <div className="user-list-error">Ошибка загрузки пользователей</div>;
  }
  if (!users) {
    return <div className="user-list-empty">Пользователи не найдены</div>;
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
};
