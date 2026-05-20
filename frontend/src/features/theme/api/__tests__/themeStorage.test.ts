import { beforeEach, describe, expect, it, vi } from "vitest";

import { THEME_STORAGE_KEY, type Theme } from "@/shared/types/theme";

import { loadThemeFromStorage, saveThemeToStorage } from "../themeStorage";

describe("themeStorage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
  });

  describe("loadThemeFromStorage", () => {
    /**
     * @description Should return stored valid theme when localStorage contains a valid theme
     * @scenario loadThemeFromStorage uses localStorage.getItem with THEME_STORAGE_KEY
     * @expected Returned value equals stored theme
     */
    it("should return stored valid theme when localStorage value is valid", () => {
      // Arrange
      const storedTheme: Theme = "dark";
      window.localStorage.setItem(THEME_STORAGE_KEY, storedTheme);

      // Act
      const result = loadThemeFromStorage();

      // Assert
      expect(result).toBe(storedTheme);
    });

    /**
     * @description Should return system when localStorage contains invalid theme value
     * @scenario loadThemeFromStorage validates storage value against THEMES
     * @expected Returned value equals "system"
     */
    it("should return system when localStorage value is invalid", () => {
      // Arrange
      window.localStorage.setItem(THEME_STORAGE_KEY, "invalid");

      // Act
      const result = loadThemeFromStorage();

      // Assert
      expect(result).toBe("system");
    });

    /**
     * @description Should return system when localStorage has no value
     * @scenario loadThemeFromStorage when localStorage.getItem returns null
     * @expected Returned value equals "system"
     */
    it("should return system when localStorage value is missing", () => {
      // Arrange
      window.localStorage.removeItem(THEME_STORAGE_KEY);

      // Act
      const result = loadThemeFromStorage();

      // Assert
      expect(result).toBe("system");
    });
  });

  describe("saveThemeToStorage", () => {
    /**
     * @description Should persist provided valid theme into localStorage
     * @scenario saveThemeToStorage is called with a theme value
     * @expected localStorage.setItem is called with THEME_STORAGE_KEY and theme
     */
    it("should save theme to localStorage when window exists", () => {
      // Arrange
      const theme: Theme = "light";

      // Act
      saveThemeToStorage(theme);

      // Assert
      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe(theme);
    });

    /**
     * @description Should not access localStorage in SSR-like environment
     * @scenario saveThemeToStorage checks typeof window === 'undefined'
     * @expected Function returns without calling localStorage
     */
    it("should not access localStorage when window is undefined", () => {
      // Arrange
      const originalWindow = (globalThis as unknown as { window?: unknown })
        .window;
      const before = window.localStorage.getItem(THEME_STORAGE_KEY);

      (globalThis as unknown as { window?: unknown }).window = undefined;

      try {
        // Act
        saveThemeToStorage("dark");

        // Assert
        // If implementation tries to access window/localStorage, it will throw.
        expect(true).toBe(true);
      } finally {
        (globalThis as unknown as { window?: unknown }).window = originalWindow;
      }

      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe(before);
    });
  });
});
