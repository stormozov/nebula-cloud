import { render } from "@testing-library/react";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  vi,
} from "vitest";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import { applyTheme } from "@/features/theme/lib/applyTheme";
import { resolveTheme } from "@/features/theme/lib/resolveTheme";
import { useSetResolvedTheme } from "@/features/theme/model/hooks";
import { setResolvedTheme } from "@/features/theme/model/slice";

import { ThemeProvider } from "../ThemeContext";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/app/store/hooks", () => ({
  useAppDispatch: vi.fn(),
  useAppSelector: vi.fn(),
}));

vi.mock("@/features/theme/lib/applyTheme", () => ({
  applyTheme: vi.fn(),
}));

vi.mock("@/features/theme/lib/resolveTheme", () => ({
  resolveTheme: vi.fn(),
}));

vi.mock("@/features/theme/model/hooks", () => ({
  useSetResolvedTheme: vi.fn(),
}));

vi.mock("@/features/theme/model/slice", () => ({
  setResolvedTheme: vi.fn(),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("ThemeProvider", () => {
  const mockDispatch = vi.fn();
  const mockSetResolved = vi.fn();
  let mockUseAppSelector: Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    (useAppDispatch as Mock).mockReturnValue(mockDispatch);
    (useSetResolvedTheme as Mock).mockReturnValue(mockSetResolved);

    mockUseAppSelector = useAppSelector as Mock;
  });

  // ---------------------------------------------------------------------------
  // THEME "system"
  // ---------------------------------------------------------------------------

  describe('when theme is "system"', () => {
    let originalMatchMedia: typeof window.matchMedia;

    beforeEach(() => {
      originalMatchMedia = window.matchMedia;
    });

    afterEach(() => {
      window.matchMedia = originalMatchMedia;
    });

    /**
     * @description Should set up media query listener and set resolved theme based on system preference
     * @scenario Theme is "system", user system preference is dark
     * @expected setResolved (hook) is called with "dark" and media query change listener is added
     */
    it("should set resolved theme to dark when system preference is dark", () => {
      // Arrange
      const mockAddEventListener = vi.fn();
      const mockRemoveEventListener = vi.fn();
      const mockMediaQueryList = {
        matches: true,
        addEventListener: mockAddEventListener,
        removeEventListener: mockRemoveEventListener,
      };
      window.matchMedia = vi.fn().mockReturnValue(mockMediaQueryList);

      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) {
            return "system";
          }
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return null;
          }
          return null;
        },
      );

      // Act
      render(
        <ThemeProvider>
          <div>child</div>
        </ThemeProvider>,
      );

      // Assert
      expect(window.matchMedia).toHaveBeenCalledWith(
        "(prefers-color-scheme: dark)",
      );
      expect(mockSetResolved).toHaveBeenCalledWith("dark");
      expect(mockAddEventListener).toHaveBeenCalledWith(
        "change",
        expect.any(Function),
      );
    });

    /**
     * @description Should set resolved theme to light when system preference is light
     * @scenario Theme is "system", user system preference is light
     * @expected setResolved (hook) is called with "light"
     */
    it("should set resolved theme to light when system preference is light", () => {
      // Arrange
      const mockMediaQueryList = {
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      };
      window.matchMedia = vi.fn().mockReturnValue(mockMediaQueryList);

      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) {
            return "system";
          }
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return null;
          }
          return null;
        },
      );

      // Act
      render(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );

      // Assert
      expect(mockSetResolved).toHaveBeenCalledWith("light");
    });

    /**
     * @description Should clean up media query listener on unmount
     * @scenario Component unmounts after setting system theme listener
     * @expected removeEventListener is called
     */
    it("should remove media query listener on unmount", () => {
      // Arrange
      const mockRemoveEventListener = vi.fn();
      const mockMediaQueryList = {
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: mockRemoveEventListener,
      };
      window.matchMedia = vi.fn().mockReturnValue(mockMediaQueryList);

      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) {
            return "system";
          }
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return null;
          }
          return null;
        },
      );

      // Act
      const { unmount } = render(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );
      unmount();

      // Assert
      expect(mockRemoveEventListener).toHaveBeenCalledWith(
        "change",
        expect.any(Function),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // THEME "not system"
  // ---------------------------------------------------------------------------

  describe('when theme is not "system"', () => {
    /**
     * @description Should dispatch setResolvedTheme with resolved value when theme changes
     * @scenario Theme is "dark", resolvedTheme is "light", resolveTheme returns "dark"
     * @expected dispatch is called with setResolvedTheme('dark')
     */
    it("should dispatch setResolvedTheme when theme is not system and resolvedTheme differs", () => {
      // Arrange
      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) return "dark";
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return "light";
          }
          return null;
        },
      );
      (resolveTheme as Mock).mockReturnValue("dark");

      // Act
      render(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );

      // Assert
      expect(resolveTheme).toHaveBeenCalledWith("dark");
      expect(mockDispatch).toHaveBeenCalledWith(setResolvedTheme("dark"));
    });

    /**
     * @description Should not dispatch when resolvedTheme already matches the resolved value
     * @scenario Theme is "light", resolvedTheme is "light", resolveTheme returns "light"
     * @expected dispatch is not called
     */
    it("should not dispatch when resolvedTheme equals resolved value", () => {
      // Arrange
      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) return "light";
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return "light";
          }
          return null;
        },
      );
      (resolveTheme as Mock).mockReturnValue("light");

      // Act
      render(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );

      // Assert
      expect(mockDispatch).not.toHaveBeenCalled();
    });

    /**
     * @description Should handle theme "light" correctly
     * @scenario Theme is "light", resolvedTheme is "dark", resolveTheme returns "light"
     * @expected dispatch is called with setResolvedTheme('light')
     */
    it('should dispatch setResolvedTheme with "light" when theme is light', () => {
      // Arrange
      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) return "light";
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return "dark";
          }
          return null;
        },
      );
      (resolveTheme as Mock).mockReturnValue("light");

      // Act
      render(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );

      // Assert
      expect(mockDispatch).toHaveBeenCalledWith(setResolvedTheme("light"));
    });
  });

  // ---------------------------------------------------------------------------
  // APPLY THEME EFFECT
  // ---------------------------------------------------------------------------

  describe("applyTheme effect", () => {
    /**
     * @description Should call applyTheme with current resolvedTheme whenever resolvedTheme changes
     * @scenario resolvedTheme changes from "light" to "dark"
     * @expected applyTheme is called with "dark"
     */
    it("should call applyTheme with resolvedTheme on each resolvedTheme change", () => {
      // Arrange
      let resolvedThemeValue = "light";
      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) {
            return "custom";
          }
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return resolvedThemeValue;
          }
          return null;
        },
      );
      (resolveTheme as Mock).mockReturnValue("light");

      const { rerender } = render(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );
      expect(applyTheme).toHaveBeenCalledWith("light");

      // Act
      resolvedThemeValue = "dark";
      mockUseAppSelector.mockImplementation(
        (selector: (state: unknown) => unknown) => {
          if (selector.toString().includes("state.theme.theme")) {
            return "custom";
          }
          if (selector.toString().includes("state.theme.resolvedTheme")) {
            return resolvedThemeValue;
          }
          return null;
        },
      );
      rerender(
        <ThemeProvider>
          <div />
        </ThemeProvider>,
      );

      // Assert
      expect(applyTheme).toHaveBeenCalledWith("dark");
    });
  });

  // ---------------------------------------------------------------------------
  // RENDERING
  // ---------------------------------------------------------------------------

  describe("rendering", () => {
    /**
     * @description Should render children without extra DOM elements
     * @scenario Provider receives children
     * @expected children are rendered directly
     */
    it("should render its children", () => {
      // Arrange
      mockUseAppSelector.mockReturnValue("light");

      // Act
      const { container } = render(
        <ThemeProvider>
          <span data-testid="child">Hello</span>
        </ThemeProvider>,
      );

      // Assert
      expect(
        container.querySelector('[data-testid="child"]'),
      ).toBeInTheDocument();
      expect(container.children.length).toBe(1);
    });
  });
});
