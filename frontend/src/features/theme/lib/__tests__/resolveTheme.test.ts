import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ColorScheme, Theme } from "@/shared/types/theme";

import { resolveTheme } from "../resolveTheme";

describe("resolveTheme", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("when theme is 'light'", () => {
    /**
     * @description Should return 'light' scheme when theme param is 'light'
     * @scenario resolveTheme('light') is called
     * @expected Returned value equals 'light'
     */
    it("should return light when theme is light", () => {
      // Arrange
      const inputTheme: Theme = "light";

      // Act
      const result = resolveTheme(inputTheme);

      // Assert
      expect(result).toBe<ColorScheme>("light");
    });
  });

  describe("when theme is 'dark'", () => {
    /**
     * @description Should return 'dark' scheme when theme param is 'dark'
     * @scenario resolveTheme('dark') is called
     * @expected Returned value equals 'dark'
     */
    it("should return dark when theme is dark", () => {
      // Arrange
      const inputTheme: Theme = "dark";

      // Act
      const result = resolveTheme(inputTheme);

      // Assert
      expect(result).toBe<ColorScheme>("dark");
    });
  });

  describe("when theme is 'system'", () => {
    /**
     * @description Should default to 'light' when window is undefined (SSR)
     * @scenario resolveTheme('system') runs in environment without window
     * @expected Returned value equals 'light'
     */
    it("should return light when theme is system and window is undefined", () => {
      // Arrange
      const originalWindow = (globalThis as unknown as { window?: unknown })
        .window;
      (globalThis as unknown as { window?: unknown }).window = undefined;

      try {
        const inputTheme: Theme = "system";

        // Act
        const result = resolveTheme(inputTheme);

        // Assert
        expect(result).toBe<ColorScheme>("light");
      } finally {
        (globalThis as unknown as { window?: unknown }).window = originalWindow;
      }
    });

    describe("when window exists", () => {
      /**
       * @description Should return 'dark' when system prefers dark
       * @scenario resolveTheme('system') uses matchMedia('(prefers-color-scheme: dark)').matches === true
       * @expected Returned value equals 'dark'
       */
      it("should return dark when system prefers dark", () => {
        // Arrange
        const matchMediaMock = vi
          .fn()
          .mockImplementation(() => ({ matches: true }));

        const originalWindow = (globalThis as unknown as { window?: unknown })
          .window;

        (globalThis as unknown as { window?: unknown }).window = {
          matchMedia: matchMediaMock,
        };

        try {
          const inputTheme: Theme = "system";

          // Act
          const result = resolveTheme(inputTheme);

          // Assert
          expect(result).toBe<ColorScheme>("dark");
          expect(matchMediaMock).toHaveBeenCalledWith(
            "(prefers-color-scheme: dark)",
          );
        } finally {
          (globalThis as unknown as { window?: unknown }).window =
            originalWindow;
        }
      });

      /**
       * @description Should return 'light' when system prefers light
       * @scenario resolveTheme('system') uses matchMedia('(prefers-color-scheme: dark)').matches === false
       * @expected Returned value equals 'light'
       */
      it("should return light when system prefers light", () => {
        // Arrange
        const matchMediaMock = vi
          .fn()
          .mockImplementation(() => ({ matches: false }));

        const originalWindow = (globalThis as unknown as { window?: unknown })
          .window;

        (globalThis as unknown as { window?: unknown }).window = {
          matchMedia: matchMediaMock,
        };

        try {
          const inputTheme: Theme = "system";

          // Act
          const result = resolveTheme(inputTheme);

          // Assert
          expect(result).toBe<ColorScheme>("light");
          expect(matchMediaMock).toHaveBeenCalledWith(
            "(prefers-color-scheme: dark)",
          );
        } finally {
          (globalThis as unknown as { window?: unknown }).window =
            originalWindow;
        }
      });
    });
  });
});
