import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useClickOutside } from "@/shared/hooks";

import { CollapsibleSearch } from "./CollapsibleSearch";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/shared/hooks", () => ({
  useClickOutside: vi.fn(),
}));

vi.mock("@/shared/ui", () => ({
  Button: vi.fn(({ ref, onClick, children, ...props }) => (
    <button data-testid="search-button" onClick={onClick} ref={ref} {...props}>
      {children || "Button"}
    </button>
  )),
  ControlledInput: vi.fn(({ ref, onKeyDown, ...props }) => (
    <input
      data-testid="search-input"
      ref={ref}
      onKeyDown={onKeyDown}
      {...props}
    />
  )),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("CollapsibleSearch", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Vitest mock typing (без any)
    const mockedUseClickOutside = vi.mocked(useClickOutside);
    mockedUseClickOutside.mockImplementation(() => {});
  });

  describe("when rendered with default props", () => {
    /**
     * @description Renders closed state with button visible and input hidden
     * @scenario Render CollapsibleSearch without any props
     * @expected Button visible, aria-hidden=false, no tabindex; Input hidden, aria-hidden=true, tabindex=-1
     */
    it("should render button and hidden input when isOpen is false", () => {
      // Arrange
      render(<CollapsibleSearch />);

      // Act
      const button = screen.getByTestId("search-button");
      const input = screen.getByTestId("search-input");

      // Assert
      expect(button).toHaveAttribute("aria-hidden", "false");
      expect(button).not.toHaveAttribute("tabIndex");
      expect(input).toHaveAttribute("aria-hidden", "true");
      expect(input).toHaveAttribute("tabIndex", "-1");
    });

    /**
     * @description Does not set placeholder when inputProps.placeholder is omitted
     * @scenario Render without inputProps.placeholder
     * @expected Input has no placeholder attribute
     */
    it("should not have placeholder when not provided", () => {
      // Arrange
      render(<CollapsibleSearch />);
      const input = screen.getByTestId("search-input");

      // Assert
      expect(input).not.toHaveAttribute("placeholder");
    });
  });

  describe("when button is clicked", () => {
    /**
     * @description Opens search input and focuses it
     * @scenario User clicks on search button
     * @expected isOpen=true, input visible and focused
     */
    it("should open input and set focus on it", async () => {
      // Arrange
      render(<CollapsibleSearch />);
      const button = screen.getByTestId("search-button");
      const input = screen.getByTestId("search-input");

      // Act
      fireEvent.click(button);

      // Assert
      expect(input).toHaveAttribute("aria-hidden", "false");
      expect(input).not.toHaveAttribute("tabIndex");
      expect(button).toHaveAttribute("aria-hidden", "true");
      expect(button).toHaveAttribute("tabIndex", "-1");
      expect(input).toHaveFocus();
    });
  });

  describe("when input is open and Escape key is pressed", () => {
    /**
     * @description Closes input and returns focus to button
     * @scenario Input open, user presses Escape
     * @expected isOpen=false, input hidden, button focused
     */
    it("should close input and focus button on Escape", () => {
      // Arrange
      render(<CollapsibleSearch />);
      const button = screen.getByTestId("search-button");
      const input = screen.getByTestId("search-input");

      // Act: open
      fireEvent.click(button);
      expect(input).toHaveFocus();

      // Act: press Escape
      fireEvent.keyDown(input, { key: "Escape" });

      // Assert
      expect(input).toHaveAttribute("aria-hidden", "true");
      expect(input).toHaveAttribute("tabIndex", "-1");
      expect(button).toHaveAttribute("aria-hidden", "false");
      expect(button).not.toHaveAttribute("tabIndex");
      expect(button).toHaveFocus();
    });
  });

  describe("when clicking outside the component", () => {
    /**
     * @description Does not close if input value is not empty
     * @scenario Input open with non-empty value, click outside
     * @expected Component stays open
     */
    it("should not close when value is not empty", () => {
      // Arrange
      let clickOutsideCallback: () => void;

      const mockedUseClickOutside = vi.mocked(useClickOutside);
      mockedUseClickOutside.mockImplementation(
        (_ref: unknown, callback: () => void) => {
          clickOutsideCallback = callback;
        },
      );
      const onChange = vi.fn();
      render(
        <CollapsibleSearch
          inputProps={{
            value: "non-empty",
            onChange,
            placeholder: "Search",
          }}
        />,
      );
      const button = screen.getByTestId("search-button");
      const input = screen.getByTestId("search-input");

      // Act: open
      fireEvent.click(button);
      expect(input).toHaveAttribute("aria-hidden", "false");

      // Act: simulate click outside
      act(() => {
        clickOutsideCallback();
      });

      // Assert
      expect(input).toHaveAttribute("aria-hidden", "false");
    });

    /**
     * @description Closes when input value is empty and click outside
     * @scenario Input open with empty value, click outside
     * @expected Component closes
     */
    it("should close when value is empty and click outside", () => {
      // Arrange
      let clickOutsideCallback: () => void;
      const mockedUseClickOutside = vi.mocked(useClickOutside);
      mockedUseClickOutside.mockImplementation(
        (_ref: unknown, callback: () => void) => {
          clickOutsideCallback = callback;
        },
      );
      render(
        <CollapsibleSearch inputProps={{ value: "", onChange: vi.fn() }} />,
      );
      const button = screen.getByTestId("search-button");
      const input = screen.getByTestId("search-input");

      // Act: open
      fireEvent.click(button);
      expect(input).toHaveAttribute("aria-hidden", "false");

      // Act: simulate click outside
      act(() => {
        clickOutsideCallback();
      });

      // Assert
      expect(input).toHaveAttribute("aria-hidden", "true");
      expect(button).toHaveAttribute("aria-hidden", "false");
    });
  });

  describe("when inputProps are provided", () => {
    /**
     * @description Passes custom placeholder to input
     * @scenario Provide inputProps.placeholder
     * @expected Input has custom placeholder
     */
    it("should render with custom placeholder", () => {
      // Arrange
      render(
        <CollapsibleSearch
          inputProps={{
            value: "",
            onChange: vi.fn(),
            placeholder: "Custom placeholder",
          }}
        />,
      );
      const input = screen.getByTestId("search-input");

      // Assert
      expect(input).toHaveAttribute("placeholder", "Custom placeholder");
    });

    /**
     * @description Forwards value and onChange to ControlledInput
     * @scenario Provide inputProps.value and onChange
     * @expected Input receives these props and triggers onChange
     */
    it("should forward value and onChange to input", () => {
      // Arrange
      const onChange = vi.fn();
      render(
        <CollapsibleSearch
          inputProps={{
            value: "test",
            onChange,
          }}
        />,
      );
      const input = screen.getByTestId("search-input") as HTMLInputElement;

      // Assert
      expect(input.value).toBe("test");
      fireEvent.change(input, { target: { value: "new" } });
      expect(onChange).toHaveBeenCalled();
    });
  });

  describe("when buttonProps are provided", () => {
    /**
     * @description Merges custom buttonProps with default button attributes
     * @scenario Provide custom buttonProps (variant, children, aria-label)
     * @expected Button receives merged props (DOM attributes)
     */
    it("should merge custom buttonProps with default ones", () => {
      // Arrange
      render(
        <CollapsibleSearch
          buttonProps={{
            variant: "primary",
            children: "Custom Button Text",
            "aria-label": "custom label",
          }}
        />,
      );
      const button = screen.getByTestId("search-button");

      // Assert
      expect(button).toHaveAttribute("aria-label", "custom label");
      expect(button).toHaveTextContent("Custom Button Text");
      expect(button).toHaveAttribute("title", "Поиск");
      expect(button).toHaveAttribute("variant", "primary");
    });
  });

  describe("when className is provided via inputProps", () => {
    /**
     * @description Applies custom className to container div
     * @scenario Provide inputProps.className
     * @expected Container div has both default and custom classes
     */
    it("should apply custom className to container", () => {
      // Arrange
      const { container } = render(
        <CollapsibleSearch
          inputProps={{
            value: "",
            onChange: vi.fn(),
            className: "custom-class",
          }}
        />,
      );
      const div = container.firstChild as HTMLElement;

      // Assert
      expect(div).toHaveClass("collapsible-search");
      expect(div).toHaveClass("custom-class");
    });
  });
});
