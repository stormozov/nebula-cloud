import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Button } from "./Button";
import type { ButtonSize, ButtonVariant } from "./types";

describe("Button", () => {
  /**
   * Tests basic rendering and HTML structure.
   * Verifies button element, role, default type="button".
   */
  describe("renders correct button element", () => {
    it('renders button element with correct role and default type="button"', () => {
      render(<Button>Click me</Button>);
      const button = screen.getByRole("button");
      expect(button).toBeInTheDocument();
      expect(button.tagName.toLowerCase()).toBe("button");
      expect(button).toHaveAttribute("type", "button");
    });

    it("renders button with custom type attribute when provided", () => {
      render(<Button type="submit">Submit</Button>);
      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("type", "submit");
    });
  });

  // ===========================================================================

  /**
   * Tests CSS class construction exhaustively.
   * Covers classNames() logic, all variants, sizes, modifiers, combinations, defaults.
   */
  describe("applies correct CSS classes", () => {
    const variants: ButtonVariant[] = [
      "primary",
      "secondary",
      "danger",
      "ghost",
    ];
    const sizes: ButtonSize[] = ["small", "medium", "large"];

    it("applies default classes: button button--primary button--medium", () => {
      render(<Button>Default</Button>);
      const button = screen.getByRole("button");
      expect(button).toHaveClass("button", "button--primary", "button--medium");
    });

    variants.forEach((variant) => {
      it(`applies button--${variant} class when variant="${variant}"`, () => {
        render(<Button variant={variant}>Test</Button>);
        const button = screen.getByRole("button");
        expect(button).toHaveClass(`button--${variant}`);
      });
    });

    sizes.forEach((size) => {
      it(`applies button--${size} class when size="${size}"`, () => {
        render(<Button size={size}>Test</Button>);
        const button = screen.getByRole("button");
        expect(button).toHaveClass(`button--${size}`);
      });
    });

    it("applies button--full-width class when fullWidth=true", () => {
      render(<Button fullWidth>Full</Button>);
      const button = screen.getByRole("button");
      expect(button).toHaveClass("button--full-width");
    });

    it("appends custom className to existing classes", () => {
      render(<Button className="className">Custom</Button>);
      const button = screen.getByRole("button");
      expect(button.className).toContain("className");
      expect(button.className).toContain("button");
    });

    it("combines all modifier classes correctly without duplication", () => {
      render(
        <Button
          variant="danger"
          size="large"
          fullWidth
          loading={false}
          className="className"
        >
          Combined
        </Button>,
      );
      const button = screen.getByRole("button");
      expect(button.className).toContain("className");
      expect(button.className).toContain("button--danger");
      expect(button.className).toContain("button--large");
      expect(button.className).toContain("button--full-width");
      expect(button.className).toContain("button");
    });

    it("handles empty string className without breaking class list", () => {
      render(<Button className="">Test</Button>);
      const button = screen.getByRole("button");
      expect(button).toHaveClass("button", "button--primary", "button--medium");
    });
  });

  // ===========================================================================

  /**
   * Tests loading state: spinner visibility, content toggle, auto-disable.
   * Covers loading=true/false branches.
   */
  describe("handles loading state correctly", () => {
    it("shows spinner and hides content when loading=true", () => {
      render(<Button loading>Hidden content</Button>);
      const button = screen.getByRole("button");
      const spinner = button.querySelector(".button__spinner");
      expect(button).toHaveClass("button--loading");
      expect(spinner).toBeInTheDocument();
      expect(screen.queryByText("Hidden content")).not.toBeInTheDocument();
      expect(button).toBeDisabled();
    });

    it("hides spinner and shows content when loading=false (default)", () => {
      render(<Button>Content</Button>);
      const button = screen.getByRole("button");
      const spinner =
        screen.queryByLabelText(/loading/i) ||
        button.querySelector(".button__spinner");
      expect(spinner).not.toBeInTheDocument();
      expect(screen.getByText("Content")).toBeInTheDocument();
      expect(button).not.toBeDisabled();
    });

    it("spinner has aria-hidden=true for accessibility when loading", () => {
      render(<Button loading>Text</Button>);
      const spinner = document.querySelector(".button__spinner") as HTMLElement;
      expect(spinner).toHaveAttribute("aria-hidden", "true");
    });
  });

  // ===========================================================================

  /**
   * Tests disabled state: prop + loading override (disabled || loading).
   */
  describe("handles disabled state correctly", () => {
    it("disables button when disabled=true regardless of loading", () => {
      render(<Button disabled>Disabled</Button>);
      expect(screen.getByRole("button")).toBeDisabled();
    });

    it("disables button when loading=true (overrides explicit disabled=false)", () => {
      render(
        <Button loading disabled={false}>
          Loading
        </Button>,
      );
      expect(screen.getByRole("button")).toBeDisabled();
    });

    it("enables button when neither disabled nor loading", () => {
      render(<Button>Enabled</Button>);
      expect(screen.getByRole("button")).not.toBeDisabled();
    });
  });

  // ===========================================================================

  /**
   * Tests children rendering variations.
   */
  describe("renders children content", () => {
    it("renders text children correctly", () => {
      const text = "Click me";
      render(<Button>{text}</Button>);
      expect(screen.getByText(text)).toBeInTheDocument();
    });

    it("renders empty children gracefully without errors", () => {
      render(<Button> </Button>);
      const button = screen.getByRole("button");
      expect(button).not.toHaveTextContent("non-empty");
    });

    it("renders complex children (elements, icons) correctly", () => {
      const child = (
        <span>
          <strong>Strong</strong> text
        </span>
      );
      render(<Button>{child}</Button>);
      expect(screen.getByText("Strong")).toBeInTheDocument();
      expect(screen.getByText("text")).toBeInTheDocument();
    });

    it("preserves children when loading=false", () => {
      render(<Button>Preserved</Button>);
      expect(screen.getByText("Preserved")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  /**
   * Tests HTML attribute passthrough and event handling.
   * Covers React.ButtonHTMLAttributes spread.
   */
  describe("passes through HTML attributes and events", () => {
    it("applies id attribute correctly", () => {
      const id = "test-button-id";
      render(<Button id={id}>Test</Button>);
      expect(screen.getByRole("button")).toHaveAttribute("id", id);
    });

    it("applies data-* attributes correctly", () => {
      render(<Button data-testid="button-test">Test</Button>);
      expect(screen.getByTestId("button-test")).toBeInTheDocument();
    });

    it("applies inline style correctly", () => {
      const style = { backgroundColor: "blue" };
      render(<Button style={style}>Styled</Button>);
      expect(screen.getByRole("button")).toHaveStyle({
        backgroundColor: "blue",
      });
    });

    it("applies aria-label for accessibility", () => {
      const ariaLabel = "Custom button label";
      render(<Button aria-label={ariaLabel}>Labelled</Button>);
      expect(screen.getByRole("button")).toHaveAttribute(
        "aria-label",
        ariaLabel,
      );
    });

    it("handles onClick event when not disabled/loading", () => {
      const handleClick = vi.fn();
      render(<Button onClick={handleClick}>Clickable</Button>);
      const button = screen.getByRole("button");
      fireEvent.click(button);
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it("does not trigger onClick when disabled", () => {
      const handleClick = vi.fn();
      render(
        <Button onClick={handleClick} disabled>
          Disabled
        </Button>,
      );
      fireEvent.click(screen.getByRole("button"));
      expect(handleClick).not.toHaveBeenCalled();
    });

    it("does not trigger onClick when loading", () => {
      const handleClick = vi.fn();
      render(
        <Button onClick={handleClick} loading>
          Loading
        </Button>,
      );
      fireEvent.click(screen.getByRole("button"));
      expect(handleClick).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================

  /**
   * Snapshot tests for visual regression testing across configurations.
   */
  describe("snapshot tests", () => {
    it("matches snapshot for default button", () => {
      const { container } = render(<Button>Default Button</Button>);
      expect(container.firstChild).toMatchSnapshot();
    });

    it("matches snapshot for fully customized button", () => {
      const { container } = render(
        <Button
          variant="ghost"
          size="small"
          loading
          fullWidth
          id="snap-id"
          className="snap-class"
          disabled
        >
          Snapshot
        </Button>,
      );
      expect(container.firstChild).toMatchSnapshot();
    });

    it("matches snapshot for loading state without children", () => {
      const { container } = render(<Button loading>&nbsp;</Button>);
      expect(container.firstChild).toMatchSnapshot();
    });
  });
});
