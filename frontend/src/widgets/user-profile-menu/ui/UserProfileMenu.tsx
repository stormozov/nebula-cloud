import { useSelector } from "react-redux";
import { useNavigate } from "react-router";

import { selectUser } from "@/entities/user";
import { useLogout } from "@/features/auth";
import type { IDropdownMenuActionItem } from "@/shared/ui";
import { Avatar, DropdownMenu } from "@/shared/ui";

import "./UserProfileMenu.scss";

/**
 * User profile menu component that displays a dropdown with user actions.
 *
 * Renders a trigger button containing the user's avatar and name. When clicked,
 * it opens a dropdown menu with options.
 */
export function UserProfileMenu() {
  const user = useSelector(selectUser);
  const navigate = useNavigate();
  const { logout, isLoading: isLogoutLoading } = useLogout();

  if (!user) return null;

  const actions: IDropdownMenuActionItem<null>[] = [
    {
      id: "profile",
      label: "Профиль",
      arialLabel: "Недоступно",
      icon: "lock",
      disabled: true,
      onClick: () => navigate("/profile"),
    },
    {
      id: "settings",
      label: "Настройки",
      arialLabel: "Недоступно",
      icon: "lock",
      disabled: true,
      onClick: () => navigate("/settings"),
    },
    {
      id: "logout",
      label: "Выйти",
      icon: "logout",
      isDanger: true,
      onClick: logout,
      disabled: isLogoutLoading,
    },
  ];

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
    </button>
  );

  return (
    <div className="user-profile-menu">
      <DropdownMenu
        trigger={trigger}
        actions={actions}
        item={null}
        placement="bottom-end"
      />
    </div>
  );
}
