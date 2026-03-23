import type { IUserListResponse } from "@/entities/user";

/**
 * Interface for the props of the UserListItem component.
 */
export interface IUserListItemProps {
  user: IUserListResponse;
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
export function UserListItem({ user }: IUserListItemProps) {
  return (
    <tr>
      <td>{user.id}</td>
      <td>{user.username}</td>
      <td>{user.email}</td>
      <td>{user.isStaff ? "Да" : "Нет"}</td>
      <td>{user.isActive ? "Да" : "Нет"}</td>
    </tr>
  );
}
