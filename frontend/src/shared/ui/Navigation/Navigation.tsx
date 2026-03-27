import classNames from "classnames";
import { NavLink } from "react-router";

import { useAppSelector } from "@/app/store/hooks";
import { selectIsStaff, type UserRoles } from "@/entities/user";
import { Icon, type IconName } from "@/shared/ui";

import "./Navigation.scss";

/**
 * Interface describing the structure of a navigation item.
 */
interface INavItem {
  to: string;
  icon?: IconName;
  label: string;
  roles?: UserRoles[];
  withIcon?: boolean;
}

/**
 * Default array of navigation items used in the application.
 */
const defaultItems: INavItem[] = [
  {
    to: "/disk",
    icon: "folder",
    label: "Мой диск",
    roles: ["user", "admin"],
    withIcon: true,
  },
  {
    to: "/admin/dashboard",
    icon: "dashboard",
    label: "Админ-панель",
    roles: ["admin"],
    withIcon: true,
  },
];

/**
 * Navigation component that renders a list of nav links based on user role.
 *
 * The component filters the provided navigation items according to the current
 * user's role, ensuring that users only see links they have permission
 * to access. If there are zero or only one visible items after filtering,
 * the component returns `null` and does not render.
 */
export function Navigation({ items = defaultItems }) {
  const isStaff = useAppSelector(selectIsStaff);
  const role = isStaff ? "admin" : "user";

  const visibleItems = items.filter(
    (item) => !item.roles || item.roles.includes(role),
  );

  if (visibleItems.length === 0 || visibleItems.length === 1) return null;

  return (
    <nav className="navigation">
      {visibleItems.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={classNames("navigation__link", {
            "navigation__link--active": window.location.pathname === item.to,
          })}
          caseSensitive
        >
          {item.icon && item.withIcon && <Icon name={item.icon} />}
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}
