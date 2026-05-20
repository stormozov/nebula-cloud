import { screen } from "@testing-library/react";
import { renderWithRouter } from "@tests/utils/renderWithRouter";
import { describe, expect, it } from "vitest";

import { Logo } from "./Logo";

describe("Logo", () => {
  const LOGO_TEXT = "Nebula Cloud";

  // ===========================================================================

  describe("renders correct DOM structure", () => {
    /**
     * @description Renders div with logo class
     * @scenario Rendering Logo component
     * @expected Div with logo class
     */
    it("renders div with logo class", () => {
      renderWithRouter(<Logo />);

      const logoDiv = screen.getByText(LOGO_TEXT).closest("div");
      expect(logoDiv).toBeInTheDocument();
      expect(logoDiv).toHaveClass("logo");

      expect(logoDiv?.querySelector("p")).toHaveTextContent(LOGO_TEXT);
    });
  });

  // ===========================================================================

  describe("applies correct CSS classes and styles", () => {
    /**
     * @description Applies correct CSS classes
     * @scenario Rendering Logo component
     * @expected Div with "logo" class
     */
    it('applies "logo" class to root div', () => {
      renderWithRouter(<Logo />);
      const logoDiv = screen.getByText(LOGO_TEXT).closest("div");
      expect(logoDiv).toHaveClass("logo");
    });
  });

  // ===========================================================================

  describe("renders fixed content", () => {
    /**
     * @description Renders exact text LOGO_TEXT
     * @scenario Rendering Logo component
     * @expected Exact text LOGO_TEXT inside p tag
     */
    it("renders exact text LOGO_TEXT inside p tag", () => {
      renderWithRouter(<Logo />);
      expect(screen.getByText(LOGO_TEXT)).toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("passes through HTML attributes to root div", () => {
    /**
     * @description Passes through id attribute to div
     * @scenario Rendering Logo component with id="test-logo-id"
     * @expected Div with id="test-logo-id"
     */
    it("applies id attribute to div", () => {
      const id = "test-logo-id";
      renderWithRouter(<Logo id={id} />);
      const logoDiv = screen.getByText(LOGO_TEXT).closest("div");
      expect(logoDiv).toHaveAttribute("id", id);
    });

    /**
     * @description Passes through data-* attributes to div
     * @scenario Rendering Logo component with data-testid="logo-test"
     * @expected Div with data-testid="logo-test"
     */
    it("applies data-* attributes", () => {
      renderWithRouter(<Logo data-testid="logo-test" />);
      expect(screen.getByTestId("logo-test")).toBeInTheDocument();
    });

    /**
     * @description Passes through style attribute to div
     * @scenario Rendering Logo component with style={{ margin: "10px" }}
     * @expected Div with style={{ margin: "10px" }}
     */
    it("applies style attribute", () => {
      const customStyle = { margin: "10px" };
      renderWithRouter(<Logo style={customStyle} />);
      const logoDiv = screen.getByText(LOGO_TEXT).closest("div");
      expect(logoDiv).toHaveStyle({ margin: "10px" });
    });

    /**
     * @description Passes through aria-label attribute to div
     * @scenario Rendering Logo component with aria-label="Nebula Cloud Logo"
     * @expected Div with aria-label="Nebula Cloud Logo"
     */
    it("applies aria-label attribute", () => {
      const ariaLabel = "Nebula Cloud Logo";
      renderWithRouter(<Logo aria-label={ariaLabel} />);
      const logoDiv = screen.getByText(LOGO_TEXT).closest("div");
      expect(logoDiv).toHaveAttribute("aria-label", ariaLabel);
    });
  });
});
