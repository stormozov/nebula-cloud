import type { ColorScheme } from "@/shared/types/theme";

/**
 * Applies a color scheme theme to the document by updating both
 * the `data-theme` attribute and the `colorScheme` style property on the root
 * element (`<html>`).
 *
 * @param scheme - The color scheme to apply. Must be a valid
 * {@link ColorScheme}.
 */
export const applyTheme = (scheme: ColorScheme): void => {
  const root = document.documentElement;
  root.setAttribute("data-theme", scheme);
  root.style.colorScheme = scheme;
};
