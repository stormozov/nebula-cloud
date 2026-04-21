import { useCallback } from "react";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import type { ColorScheme, Theme } from "@/shared/types/theme";

import { saveThemeToStorage } from "../api/themeStorage";
import { setResolvedTheme, setTheme } from "./slice";

/**
 * Custom React hook that provides access to the user's selected theme and
 * a function to change it.
 */
export const useTheme = () => {
  const dispatch = useAppDispatch();
  const theme = useAppSelector((state) => state.theme.theme);

  const changeTheme = useCallback(
    (newTheme: Theme) => {
      dispatch(setTheme(newTheme));
      saveThemeToStorage(newTheme);
    },
    [dispatch],
  );

  return { theme, setTheme: changeTheme };
};

/**
 * Custom React hook that returns the currently resolved color scheme.
 */
export const useResolvedTheme = (): ColorScheme =>
  useAppSelector((state) => state.theme.resolvedTheme);

/**
 * Custom React hook that returns a memoized function to update the resolved
 * theme in the store.
 */
export const useSetResolvedTheme = () => {
  const dispatch = useAppDispatch();
  return useCallback(
    (scheme: ColorScheme) => dispatch(setResolvedTheme(scheme)),
    [dispatch],
  );
};
