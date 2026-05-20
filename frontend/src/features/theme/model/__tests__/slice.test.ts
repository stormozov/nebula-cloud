import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ColorScheme, Theme } from "@/shared/types/theme";

import { loadThemeFromStorage } from "../../api/themeStorage";
import { resolveTheme } from "../../lib/resolveTheme";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../../api/themeStorage", () => ({
  loadThemeFromStorage: vi.fn(),
}));

vi.mock("../../lib/resolveTheme", () => ({
  resolveTheme: vi.fn(),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("themeSlice (slice.ts)", () => {
  const mockLoadThemeFromStorage = loadThemeFromStorage as unknown as {
    mockReturnValueOnce: (value: Theme) => void;
  };

  const mockResolveTheme = resolveTheme as unknown as {
    mockReturnValueOnce: (value: ColorScheme) => void;
    mockReturnValue: (value: ColorScheme) => void;
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
  });

  describe("when slice initializes", () => {
    /**
     * @description Should set theme from loadThemeFromStorage during slice initialization
     * @scenario slice.ts initialState is evaluated with loadThemeFromStorage mocked
     * @expected state.theme equals mocked loadThemeFromStorage return value
     */
    it("should set theme from storage when slice initializes", async () => {
      // Arrange
      const initialTheme: Theme = "dark";
      mockLoadThemeFromStorage.mockReturnValueOnce(initialTheme);
      mockResolveTheme.mockReturnValueOnce("light" as ColorScheme);

      // Act
      const mod = await import("../slice");
      const state = mod.themeReducer(undefined, { type: "@@INIT" });

      // Assert
      expect(state.theme).toBe(initialTheme);
    });

    /**
     * @description Should set resolvedTheme using resolveTheme(loadThemeFromStorage) during slice initialization
     * @scenario slice.ts initialState is evaluated with loadThemeFromStorage and resolveTheme mocked
     * @expected state.resolvedTheme equals mocked resolveTheme output
     */
    it("should set resolvedTheme from resolveTheme(loadThemeFromStorage) when slice initializes", async () => {
      // Arrange
      const initialTheme: Theme = "system";
      const initialResolved: ColorScheme = "light";
      mockLoadThemeFromStorage.mockReturnValueOnce(initialTheme);
      mockResolveTheme.mockReturnValueOnce(initialResolved);

      // Act
      const mod = await import("../slice");
      const state = mod.themeReducer(undefined, { type: "@@INIT" });

      // Assert
      expect(state.resolvedTheme).toBe(initialResolved);
    });
  });

  describe("when setTheme reducer is dispatched", () => {
    /**
     * @description Should update both theme and resolvedTheme when setTheme is dispatched
     * @scenario dispatch setTheme('system') with resolveTheme mocked
     * @expected state.theme equals payload and state.resolvedTheme equals resolveTheme(payload)
     */
    it("should update theme and resolvedTheme when setTheme is dispatched", async () => {
      // Arrange
      const payload: Theme = "system";
      const currentState = {
        theme: "light" as Theme,
        resolvedTheme: "light" as ColorScheme,
      };

      const resolved: ColorScheme = "dark";
      mockResolveTheme.mockReturnValue(resolved);

      const mod = await import("../slice");

      // Act
      const nextState = mod.themeReducer(currentState, mod.setTheme(payload));

      // Assert
      expect(nextState.theme).toBe(payload);
      expect(nextState.resolvedTheme).toBe(resolved);
    });
  });

  describe("when setResolvedTheme reducer is dispatched", () => {
    /**
     * @description Should update resolvedTheme only when setResolvedTheme is dispatched
     * @scenario dispatch setResolvedTheme('light')
     * @expected state.resolvedTheme changes while state.theme remains unchanged
     */
    it("should update resolvedTheme only when setResolvedTheme is dispatched", async () => {
      // Arrange
      const mod = await import("../slice");
      const currentState = {
        theme: "dark" as Theme,
        resolvedTheme: "dark" as ColorScheme,
      };

      const newResolved: ColorScheme = "light";

      // Act
      const nextState = mod.themeReducer(
        currentState,
        mod.setResolvedTheme(newResolved),
      );

      // Assert
      expect(nextState.theme).toBe(currentState.theme);
      expect(nextState.resolvedTheme).toBe(newResolved);
    });
  });
});
