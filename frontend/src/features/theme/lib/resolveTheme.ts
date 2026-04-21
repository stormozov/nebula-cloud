import type { ColorScheme, Theme } from "@/shared/types/theme";

/**
 * Determines the user's system-level color scheme preference.
 */
const getSystemColorScheme = (): ColorScheme =>
  window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";

/**
 * Resolves the effective color scheme based on the given theme setting.
 *
 * @param theme - The user-selected theme. Can be `"light"`, `"dark"`,
 * or `"system"`.
 */
export const resolveTheme = (theme: Theme): ColorScheme => {
  return theme === "system"
    ? typeof window === "undefined"
      ? "light"
      : getSystemColorScheme()
    : theme;
};
