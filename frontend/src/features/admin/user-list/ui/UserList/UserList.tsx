import { toast } from "react-toastify";

import type { IUserListResponse, UserListItemCopyField } from "@/entities/user";
import { copyUserField } from "@/entities/user/model/utils";
import {
  type IListStates,
  type IListStatesRenders,
  ListState,
} from "@/shared/ui";

import { UserListItemMemo } from "../UserListItem/UserListItem";

import "./UserList.scss";

const USER_LIST_HEADER = ["ID", "Логин", "Email", "Админ", "Активен"];

/**
 * Interface for the props of the UserList component.
 */
interface IUserListProps {
  /** The list of users to display. */
  users: IUserListResponse[] | undefined;
  /** Properties for the loading, error, and empty states. */
  states?: IListStates;
  /** Custom rendering functions for the loading, error, and empty states. */
  renders?: IListStatesRenders;
  /** Callback function to handle user selection. */
  onSelectUser: (userId: number) => void;
}

/**
 * Represents a list of users.
 */
export function UserList({
  users,
  states = {},
  renders = {},
  onSelectUser,
}: IUserListProps) {
  const handleCopyField = async (
    user: IUserListResponse,
    field: UserListItemCopyField,
  ) => {
    await copyUserField(
      user,
      field,
      (message) => toast.success(message, { autoClose: 1500 }),
      () => toast.error("Не удалось скопировать поле", { autoClose: 1500 }),
    );
  };

  return (
    <ListState
      states={{ ...states, itemsCount: users?.length }}
      renders={renders}
    >
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
              <UserListItemMemo
                key={user.id}
                user={user}
                onSelectUser={onSelectUser}
                onCopyField={handleCopyField}
              />
            ))}
          </tbody>
        </table>
      </div>
    </ListState>
  );
}
