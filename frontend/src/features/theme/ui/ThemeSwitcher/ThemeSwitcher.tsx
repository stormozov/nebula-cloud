import { useCallback } from "react";

import { THEMES, type Theme } from "@/shared/types/theme";
import { Button } from "@/shared/ui";

import { useTheme } from "../../model/hooks";

/**
 * A mapping of theme keys to their corresponding localized display labels
 * in Russian.
 */
const themeLabels: Record<Theme, string> = {
  light: "Светлая",
  dark: "Тёмная",
  system: "Системная",
};

/**
 * A React component that renders a theme switcher interface, allowing users
 * to select between available themes (light, dark, system).
 */
export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme();

  const handleThemeChange = useCallback(
    (newTheme: Theme) => () => setTheme(newTheme),
    [setTheme],
  );

  return (
    <div role="radiogroup" aria-label="Выбор темы оформления">
      {THEMES.map((t) => (
        <Button
          key={t}
          variant="outline"
          size="small"
          className={`theme-btn ${theme === t ? "active" : ""}`}
          aria-pressed={theme === t}
          onClick={handleThemeChange(t)}
        >
          {themeLabels[t]}
        </Button>
      ))}
    </div>
  );
}
