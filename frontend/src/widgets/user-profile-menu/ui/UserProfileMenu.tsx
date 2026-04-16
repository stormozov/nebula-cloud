import { useSelector } from "react-redux";

import { selectUser } from "@/entities/user";
import { Avatar, Badge, DropdownMenu } from "@/shared/ui";

import { useProfileMenuActions } from "../lib/useProfileMenuActions";

import "./UserProfileMenu.scss";

/**
 * User profile menu component that displays a dropdown with user actions.
 *
 * Renders a trigger button containing the user's avatar and name. When clicked,
 * it opens a dropdown menu with options.
 */
export function UserProfileMenu() {
  const user = useSelector(selectUser);

  const actions = useProfileMenuActions();

  if (!user) return null;

  const trigger = (
    <button
      type="button"
      className="user-profile-menu__trigger"
      aria-label="Меню пользователя"
    >
      <Avatar
        src=""
        alt={user.fullName || user.username}
        size="sm"
        className="user-profile-menu__avatar"
      />

      <span className="user-profile-menu__name">
        {user.fullName || user.username}
      </span>

      {user.isStaff && (
        <Badge
          variant="info-light"
          position="bottom-center"
          className="user-profile-menu__badge"
        >
          Админ
        </Badge>
      )}
    </button>
  );

  return (
    <div className="user-profile-menu">
      <DropdownMenu
        trigger={trigger}
        items={actions}
        item={null}
        placement="bottom-end"
      />
    </div>
  );
}
