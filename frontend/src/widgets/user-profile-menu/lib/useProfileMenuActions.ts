import { useCallback, useMemo } from "react";
import { useNavigate } from "react-router";

import { useLogout } from "@/features/auth";
import type { DropdownMenuItem } from "@/shared/ui";

/**
 * Custom hook that constructs a list of menu items for the user profile
 * dropdown.
 */
export const useProfileMenuActions = () => {
  const navigate = useNavigate();

  const { logout, isLoading: isLogoutLoading } = useLogout();

  const addSeparator = useCallback(
    (items: DropdownMenuItem<null>[]) => {
      if (items.length > 0) items.push({ type: "separator" });
    },
    [],
  );

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
    items.push({
      id: "logout",
      label: "Выйти",
      icon: "logout",
      isDanger: true,
      onClick: logout,
      disabled: isLogoutLoading,
    });

    return items;
  }, [navigate, logout, isLogoutLoading, addSeparator]);

  return actions;
};
