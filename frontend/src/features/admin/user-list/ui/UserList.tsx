import { useGetUsersQuery } from "@/entities/user";
import { UserListItem } from "./UserListItem";

const USER_LIST_HEADER = ["ID", "Логин", "Email", "Админ", "Активен"];

/**
 * Represents a list of users.
 */
export const UserList = () => {
  const { data: users, isLoading, error } = useGetUsersQuery();

  if (isLoading) return <div>Загрузка...</div>;
  if (error) return <div>Ошибка загрузки пользователей</div>;
  if (!users) return <div>Пользователи не найдены</div>;

  return (
    <table className="user-list">
      <thead>
        <tr>
          {USER_LIST_HEADER.map((header) => (
            <th key={header}>{header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {users?.map((user) => (
          <UserListItem key={user.id} user={user} />
        ))}
      </tbody>
    </table>
  );
};
