import { useEffect } from "react";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import { applyTheme } from "@/features/theme/lib/applyTheme";
import { resolveTheme } from "@/features/theme/lib/resolveTheme";
import { useSetResolvedTheme } from "@/features/theme/model/hooks";
import { setResolvedTheme } from "@/features/theme/model/slice";

/**
 * Props interface for the {@link ThemeProvider} component.
 */
interface ThemeProviderProps {
  /** The child elements to be rendered within the theme provider. */
  children: React.ReactNode;
}

/**
 * A React context provider component that manages and applies the application's
 * color theme.
 *
 * @example
 * ```tsx
 * <ThemeProvider>
 *   <App />
 * </ThemeProvider>
 * ```
 */
export function ThemeProvider({ children }: ThemeProviderProps) {
  const dispatch = useAppDispatch();
  const theme = useAppSelector((state) => state.theme.theme);
  const resolvedTheme = useAppSelector((state) => state.theme.resolvedTheme);
  const setResolved = useSetResolvedTheme();

  // The effect for tracking the system theme
  useEffect(() => {
    if (theme !== "system") return;

    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = (e: MediaQueryListEvent | MediaQueryList) => {
      const newScheme = e.matches ? "dark" : "light";
      setResolved(newScheme);
    };

    // Initial application of the system theme
    handleChange(mediaQuery);
    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
  }, [theme, setResolved]);

  // When changing the selected theme (not system), update resolvedTheme
  useEffect(() => {
    if (theme === "system") return;
    const scheme = resolveTheme(theme);
    if (scheme !== resolvedTheme) dispatch(setResolvedTheme(scheme));
  }, [theme, resolvedTheme, dispatch]);

  // Applying resolvedTheme to the DOM
  useEffect(() => applyTheme(resolvedTheme), [resolvedTheme]);

  return <>{children}</>;
}
