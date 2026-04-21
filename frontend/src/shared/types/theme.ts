/**
 * Readonly array of valid theme keys that the application supports.
 */
export const THEMES = ["light", "dark", "system"] as const;

/**
 * Union type representing all possible theme values.
 */
export type Theme = (typeof THEMES)[number];

/**
 * Readonly array of valid color scheme values that can be applied to the DOM.
 */
export const COLOR_SCHEMES = ["light", "dark"] as const;

/**
 * Union type representing the valid color schemes.
 */
export type ColorScheme = (typeof COLOR_SCHEMES)[number];

/**
 * The key used to store and retrieve the user's theme preference in LS.
 */
export const THEME_STORAGE_KEY = "app-theme";
