import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useNavigate } from "react-router";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { BackButton } from "./BackButton";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("react-router", () => ({
  useNavigate: vi.fn(),
}));

vi.mock("../../Icon", () => ({
  Icon: () => <span data-testid="mock-icon" />,
}));

// =============================================================================
// TESTS
// =============================================================================

describe("BackButton", () => {
  const mockNavigate = useNavigate as Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    mockNavigate.mockReturnValue(vi.fn());
  });

  describe("navigation behavior", () => {
    /**
     * @description Should call navigate(-1) when button is clicked
     * @scenario User clicks the back button
     * @expected navigate is called with -1 exactly once
     */
    it("should call navigate with -1 when clicked", async () => {
      // Arrange
      const navigateFn = vi.fn();
      mockNavigate.mockReturnValue(navigateFn);
      render(<BackButton />);

      // Act
      await userEvent.click(
        screen.getByRole("button", { name: /вернуться назад/i }),
      );

      // Assert
      expect(navigateFn).toHaveBeenCalledTimes(1);
      expect(navigateFn).toHaveBeenCalledWith(-1);
    });
  });

  describe("text rendering", () => {
    /**
     * @description Should display default text "Назад" when no text prop is provided
     * @scenario Render BackButton without text prop
     * @expected Button children contains "Назад"
     */
    it('should display default text "Назад" when text prop is not provided', () => {
      // Arrange & Act
      render(<BackButton />);

      // Assert
      expect(screen.getByRole("button")).toHaveTextContent("Назад");
    });

    /**
     * @description Should display custom text when text prop is provided
     * @scenario Render BackButton with text="Go back"
     * @expected Button children contains "Go back"
     */
    it("should display custom text when text prop is provided", () => {
      // Arrange & Act
      render(<BackButton text="Go back" />);

      // Assert
      expect(screen.getByRole("button")).toHaveTextContent("Go back");
    });
  });

  describe("accessibility attributes", () => {
    /**
     * @description Should have correct aria-label and title attributes
     * @scenario Render BackButton
     * @expected Button has aria-label="Вернуться назад" and title="Вернуться назад"
     */
    it("should have aria-label and title attributes for accessibility", () => {
      // Arrange & Act
      render(<BackButton />);

      // Assert
      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("aria-label", "Вернуться назад");
      expect(button).toHaveAttribute("title", "Вернуться назад");
    });
  });
});
