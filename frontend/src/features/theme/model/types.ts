import type { ColorScheme, Theme } from "@/shared/types/theme";

/**
 * Interface describing the structure of the theme state in the Redux store.
 */
export interface ThemeState {
  /** The user's selected theme preference. */
  theme: Theme;
  /** The currently applied color scheme, derived from the `theme` setting. */
  resolvedTheme: ColorScheme;
}
