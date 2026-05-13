import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Theme } from "@/shared/types/theme";
import { ThemeSwitcher } from "../ThemeSwitcher";

vi.mock("@/features/theme/model/hooks", () => ({
  useTheme: vi.fn(),
}));

import { useTheme } from "@/features/theme/model/hooks";


const typedUseTheme = useTheme as unknown as {
  mockReturnValue: (value: { theme: Theme; setTheme: (t: Theme) => void }) => void;
};

describe("ThemeSwitcher", () => {
  const user = userEvent.setup();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when component renders theme buttons", () => {
    /**
     * @description Should render radiogroup with three theme options
     * @scenario ThemeSwitcher is rendered with a mocked useTheme hook
     * @expected radiogroup and 3 buttons are visible
     */
    it("should render a radiogroup and theme buttons when mounted", () => {
      // Arrange
      const setTheme = vi.fn();
      typedUseTheme.mockReturnValue({ theme: "light", setTheme });

      // Act
      render(<ThemeSwitcher />);

      // Assert
      const radiogroup = screen.getByRole("radiogroup", { name: /выбор темы/i });
      expect(radiogroup).toBeInTheDocument();

      const lightButton = within(radiogroup).getByRole("button", { name: /светлая/i });
      const darkButton = within(radiogroup).getByRole("button", { name: /тёмная/i });
      const systemButton = within(radiogroup).getByRole("button", { name: /системная/i });

      expect(lightButton).toBeInTheDocument();
      expect(darkButton).toBeInTheDocument();
      expect(systemButton).toBeInTheDocument();
    });

    /**
     * @description Should mark current theme button as aria-pressed=true
     * @scenario ThemeSwitcher receives 'dark' as current theme from useTheme
     * @expected only dark button is marked pressed
     */
    it("should set aria-pressed on the active theme button when theme is dark", () => {
      // Arrange
      const setTheme = vi.fn();
      typedUseTheme.mockReturnValue({ theme: "dark", setTheme });

      // Act
      render(<ThemeSwitcher />);

      // Assert
      const radiogroup = screen.getByRole("radiogroup", { name: /выбор темы/i });
      const lightButton = within(radiogroup).getByRole("button", { name: /светлая/i });
      const darkButton = within(radiogroup).getByRole("button", { name: /тёмная/i });
      const systemButton = within(radiogroup).getByRole("button", { name: /системная/i });

      expect(lightButton).toHaveAttribute("aria-pressed", "false");
      expect(darkButton).toHaveAttribute("aria-pressed", "true");
      expect(systemButton).toHaveAttribute("aria-pressed", "false");
    });
  });

  describe("when user clicks a theme button", () => {
    /**
     * @description Should call setTheme with selected theme when clicking button
     * @scenario user clicks the light theme button
     * @expected setTheme is called with 'light'
     */
    it("should call setTheme when user selects light theme", async () => {
      // Arrange
      const setTheme = vi.fn();
      typedUseTheme.mockReturnValue({ theme: "dark", setTheme });

      // Act
      render(<ThemeSwitcher />);
      await user.click(screen.getByRole("button", { name: /светлая/i }));

      // Assert
      expect(setTheme).toHaveBeenCalledTimes(1);
      expect(setTheme).toHaveBeenCalledWith("light");
    });

    /**
     * @description Should update pressed state attribute according to theme prop
     * @scenario ThemeSwitcher is rerendered with updated theme after setTheme call
     * @expected aria-pressed moves to newly provided theme
     */
    it("should render new aria-pressed state when theme prop changes", async () => {
      // Arrange
      const setTheme = vi.fn();
      const renderWithTheme = (theme: Theme) => {
        typedUseTheme.mockReturnValue({ theme, setTheme });
        return render(<ThemeSwitcher />);
      };

      // Act
      const { rerender } = renderWithTheme("light");

      await user.click(screen.getByRole("button", { name: /системная/i }));

      // emulate store update
      typedUseTheme.mockReturnValue({ theme: "system", setTheme });
      rerender(<ThemeSwitcher />);

      // Assert
      const radiogroup = screen.getByRole("radiogroup", { name: /выбор темы/i });
      const lightButton = within(radiogroup).getByRole("button", { name: /светлая/i });
      const systemButton = within(radiogroup).getByRole("button", { name: /системная/i });

      expect(lightButton).toHaveAttribute("aria-pressed", "false");
      expect(systemButton).toHaveAttribute("aria-pressed", "true");
    });
  });
});

