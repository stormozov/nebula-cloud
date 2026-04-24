import classNames from "classnames";
import { useCallback, useMemo } from "react";
import { useNavigate } from "react-router";

import { useLogout } from "@/features/auth";
import { useTheme } from "@/features/theme";
import type { Theme } from "@/shared/types/theme";
import type { DropdownMenuItem, IconName } from "@/shared/ui";

const THEME_OPTIONS: Array<{ id: Theme; label: string; icon: IconName }> = [
  { id: "light", label: "Светлая", icon: "sun" },
  { id: "dark", label: "Тёмная", icon: "moon" },
  { id: "system", label: "Системная", icon: "monitor" },
];

/**
 * Custom hook that constructs a list of menu items for the user profile
 * dropdown.
 */
export const useProfileMenuActions = () => {
  const navigate = useNavigate();

  const { logout, isLoading: isLogoutLoading } = useLogout();
  const { theme: currentTheme, setTheme } = useTheme();

  const addSeparator = useCallback((items: DropdownMenuItem<null>[]) => {
    if (items.length > 0) items.push({ type: "separator" });
  }, []);

  const actions = useMemo(() => {
    const items: DropdownMenuItem<null>[] = [];

    items.push({
      id: "profile",
      label: "Профиль",
      arialLabel: "Недоступно",
      icon: "lock",
      disabled: true,
      onClick: () => navigate("/profile"),
    });

    items.push({
      id: "settings",
      label: "Настройки",
      arialLabel: "Недоступно",
      icon: "lock",
      disabled: true,
      onClick: () => navigate("/settings"),
    });

    addSeparator(items);

    THEME_OPTIONS.forEach(({ id, label, icon }) => {
      items.push({
        id: `theme-${id}`,
        label: `${label}`,
        arialLabel: `Тема: ${label}`,
        icon,
        classNames: classNames({
          "is-active": currentTheme === id,
        }),
        disabled: currentTheme === id,
        onClick: () => setTheme(id),
      });
    });

    addSeparator(items);

    items.push({
      id: "logout",
      label: "Выйти",
      icon: "logout",
      isDanger: true,
      onClick: logout,
      disabled: isLogoutLoading,
    });

    return items;
  }, [navigate, logout, isLogoutLoading, addSeparator, currentTheme, setTheme]);

  return actions;
};
