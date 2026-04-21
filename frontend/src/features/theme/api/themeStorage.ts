import { THEME_STORAGE_KEY, THEMES, type Theme } from "@/shared/types/theme";

/**
 * Type guard function that checks if a given value is a valid theme.
 *
 * @param value - The value to check, which can be a string or null.
 * @returns A boolean indicating whether the value is a valid `Theme`.
 */
const isValidTheme = (value: string | null): value is Theme =>
  THEMES.includes(value as Theme);

/**
 * Loads the user's theme preference from local storage.
 *
 * @returns The theme retrieved from storage, or "system" if not available
 * or invalid.
 */
export const loadThemeFromStorage = (): Theme => {
  if (typeof window === "undefined") return "system";
  const stored = localStorage.getItem(THEME_STORAGE_KEY);
  return isValidTheme(stored) ? stored : "system";
};

/**
 * Saves the specified theme to local storage.
 *
 * @param theme - The theme to save to local storage.
 */
export const saveThemeToStorage = (theme: Theme): void => {
  if (typeof window === "undefined") return;
  localStorage.setItem(THEME_STORAGE_KEY, theme);
};
