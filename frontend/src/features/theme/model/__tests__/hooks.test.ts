import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import type { ColorScheme, Theme } from "@/shared/types/theme";

import { saveThemeToStorage } from "../../api/themeStorage";
import { useResolvedTheme, useSetResolvedTheme, useTheme } from "../hooks";

// =============================================================================
// MOCKS
// =============================================================================

const mockDispatch = vi.fn();
const mockSetTheme = vi.fn();
const mockSetResolvedTheme = vi.fn();

vi.mock("@/app/store/hooks", () => ({
  useAppDispatch: vi.fn(),
  useAppSelector: vi.fn(),
}));

vi.mock("../../api/themeStorage", () => ({
  saveThemeToStorage: vi.fn(),
}));

vi.mock("../slice", () => ({
  setTheme: (theme: Theme) => mockSetTheme(theme),
  setResolvedTheme: (scheme: ColorScheme) => mockSetResolvedTheme(scheme),
}));

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");

  return {
    ...actual,
    useCallback: (fn: unknown) => fn,
  };
});

// =============================================================================
// TESTS
// =============================================================================

describe("theme hooks (hooks.ts)", () => {
  const typedUseAppDispatch = useAppDispatch as unknown as {
    mockReturnValue: (value: typeof mockDispatch) => void;
  };

  const typedUseAppSelector = useAppSelector as unknown as {
    mockImplementation: (
      impl: (selectorFn: (state: unknown) => unknown) => unknown,
    ) => void;
  };

  beforeEach(() => {
    vi.clearAllMocks();

    typedUseAppDispatch.mockReturnValue(mockDispatch);
  });

  describe("useTheme", () => {
    /**
     * @description Should return theme from selector and dispatch setTheme plus persist it
     * @scenario useTheme hook is used with selector returning a Theme value and then returned setTheme callback is invoked
     * @expected dispatch receives setTheme action and saveThemeToStorage is called with the same theme
     */
    it("should return theme from selector and should persist and dispatch when setTheme callback is called", () => {
      // Arrange
      const currentTheme: Theme = "dark";

      typedUseAppSelector.mockImplementation((selectorFn) => {
        const fn = selectorFn as (state: { theme: { theme: Theme } }) => Theme;
        return fn({ theme: { theme: currentTheme } });
      });

      const expectedAction = { type: "theme/setTheme", payload: currentTheme };
      mockSetTheme.mockReturnValue(expectedAction);

      // Act
      const { theme, setTheme } = useTheme();
      setTheme(currentTheme);

      // Assert
      expect(theme).toBe(currentTheme);
      expect(mockSetTheme).toHaveBeenCalledWith(currentTheme);
      expect(mockDispatch).toHaveBeenCalledWith(expectedAction);

      expect(
        saveThemeToStorage as unknown as typeof vi.fn,
      ).toHaveBeenCalledWith(currentTheme);
    });
  });

  describe("useResolvedTheme", () => {
    /**
     * @description Should return resolvedTheme from selector
     * @scenario useResolvedTheme hook reads state.theme.resolvedTheme
     * @expected returned value equals selector output
     */
    it("should return resolvedTheme when selector provides resolved scheme", () => {
      // Arrange
      const resolved: ColorScheme = "light";

      typedUseAppSelector.mockImplementation((selectorFn) => {
        const fn = selectorFn as (state: {
          theme: { resolvedTheme: ColorScheme };
        }) => ColorScheme;
        return fn({ theme: { resolvedTheme: resolved } });
      });

      // Act
      const scheme = useResolvedTheme();

      // Assert
      expect(scheme).toBe(resolved);
    });
  });

  describe("useSetResolvedTheme", () => {
    /**
     * @description Should provide callback that dispatches setResolvedTheme
     * @scenario useSetResolvedTheme returns callback and callback is invoked with ColorScheme
     * @expected dispatch receives setResolvedTheme action
     */
    it("should dispatch setResolvedTheme action when returned callback is called", () => {
      // Arrange
      const scheme: ColorScheme = "dark";

      const expectedAction = {
        type: "theme/setResolvedTheme",
        payload: scheme,
      };
      mockSetResolvedTheme.mockReturnValue(expectedAction);

      // Act
      const setResolvedTheme = useSetResolvedTheme();
      setResolvedTheme(scheme);

      // Assert
      expect(mockSetResolvedTheme).toHaveBeenCalledWith(scheme);
      expect(mockDispatch).toHaveBeenCalledWith(expectedAction);
    });
  });
});
