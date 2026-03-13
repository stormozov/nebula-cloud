import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  Heading,
  type HeadingAlign,
  type HeadingLevel,
  type HeadingSize,
  type HeadingVariant,
} from "./Heading";

/**
 * Comprehensive tests for Heading component ensuring 100% coverage.
 * Tests are grouped by functionality: structure, styling, content, passthrough.
 * Each test has a clear scenario describing expected behavior.
 */
describe("Heading", () => {
  /**
   * Tests rendering of correct HTML tag based on level prop.
   * Covers HEADING_TAGS mapping and default level=1.
   */
  describe("renders correct HTML tag for each level", () => {
    const testCases: Array<[level: HeadingLevel, expectedTag: string]> = [
      [1, "h1"],
      [2, "h2"],
      [3, "h3"],
      [4, "h4"],
      [5, "h5"],
      [6, "h6"],
    ];

    /**
     * @description Verifies correct HTML tag rendering for each level
     * @scenario Rendering Heading component with different levels
     * @expected Correct HTML tag for each level
     */
    testCases.forEach(([level, expectedTag]) => {
      it(`renders ${expectedTag} tag when level is ${level}`, () => {
        render(<Heading level={level}>Test Heading</Heading>);
        const heading = screen.getByRole("heading", { level: level as number });
        expect(heading).toBeInTheDocument();
        expect(heading.tagName.toLowerCase()).toBe(expectedTag);
      });
    });

    /**
     * @description Verifies default level=1 when no level prop provided
     * @scenario Rendering Heading component without level prop
     * @expected h1 tag rendered by default
     */
    it("renders h1 tag by default when level is not provided", () => {
      render(<Heading>Test Heading</Heading>);
      const heading = screen.getByRole("heading", { level: 1 });
      expect(heading.tagName.toLowerCase()).toBe("h1");
    });
  });

  // ===========================================================================

  /**
   * Tests className construction with all variants, aligns, sizes, and custom className.
   * Covers classNames() logic and all prop combinations exhaustively.
   */
  describe("applies correct CSS classes", () => {
    const variants: HeadingVariant[] = [
      "primary",
      "secondary",
      "tertiary",
      "inverse",
      "link",
      "accent",
    ];
    const aligns: HeadingAlign[] = ["left", "center", "right"];
    const sizes: HeadingSize[] = ["sm", "md", "lg", "xl", "2xl"];

    /**
     * @description Verifies base CSS class application for component recognition
     * @scenario Default Heading render without modifiers
     * @expected Container element has "heading" base class
     */
    it("applies default classes: heading heading--primary heading--left heading--md", () => {
      render(<Heading>Test</Heading>);
      const heading = screen.getByRole("heading");
      expect(heading).toHaveClass(
        "heading",
        "heading--primary",
        "heading--left",
        "heading--md",
      );
    });

    /**
     * @description Verifies all variant combinations are applied correctly
     * @scenario Testing all variant combinations
     * @expected Each variant class is applied correctly
     */
    variants.forEach((variant) => {
      it(`applies heading--${variant} class when variant="${variant}"`, () => {
        render(<Heading variant={variant}>Test</Heading>);
        const heading = screen.getByRole("heading");
        expect(heading).toHaveClass(`heading--${variant}`);
      });
    });

    /**
     * @description Verifies all align combinations are applied correctly
     * @scenario Testing all align combinations
     * @expected Each align class is applied correctly
     */
    aligns.forEach((align) => {
      it(`applies heading--${align} class when align="${align}"`, () => {
        render(<Heading align={align}>Test</Heading>);
        const heading = screen.getByRole("heading");
        expect(heading).toHaveClass(`heading--${align}`);
      });
    });

    /**
     * @description Verifies all size combinations are applied correctly
     * @scenario Testing all size combinations
     * @expected Each size class is applied correctly
     */
    sizes.forEach((size) => {
      it(`applies heading--${size} class when size="${size}"`, () => {
        render(<Heading size={size}>Test</Heading>);
        const heading = screen.getByRole("heading");
        expect(heading).toHaveClass(`heading--${size}`);
      });
    });

    /**
     * @description Verifies combined modifier classes are applied correctly
     * @scenario Testing combined modifier classes
     * @expected Each modifier class is applied correctly
     */
    it("combines all modifier classes correctly", () => {
      render(
        <Heading
          level={3}
          variant="accent"
          align="center"
          size="xl"
          className="custom-class"
        >
          Combined
        </Heading>,
      );
      const heading = screen.getByRole("heading", { level: 3 });
      expect(heading).toHaveClass(
        "heading",
        "heading--accent",
        "heading--center",
        "heading--xl",
        "custom-class",
      );
    });

    /**
     * @description Verifies empty string className is handled gracefully
     * @scenario Testing empty string className
     * @expected Empty string className is handled gracefully
     */
    it("handles empty string className without breaking", () => {
      render(<Heading className="">Test Heading</Heading>);
      const heading = screen.getByRole("heading");
      expect(heading).toHaveClass(
        "heading",
        "heading--primary",
        "heading--left",
        "heading--md",
      );
    });
  });

  // ===========================================================================

  /**
   * Tests content rendering.
   */
  describe("renders children content", () => {
    /**
     * @description Verifies children text content is rendered correctly
     * @scenario Rendering Heading component with text children
     * @expected Children text content is rendered correctly
     */
    it("renders provided children text content", () => {
      const text = "Hello Heading";
      render(<Heading>{text}</Heading>);
      expect(screen.getByText(text)).toBeInTheDocument();
    });

    /**
     * @description Verifies empty children are handled gracefully
     * @scenario Rendering Heading component with empty children
     * @expected Empty children are handled gracefully
     */
    it("renders empty children gracefully", () => {
      render(<Heading>{null}</Heading>);
      const heading = screen.getByRole("heading");
      expect(heading).toBeEmptyDOMElement();
    });

    /**
     * @description Verifies complex children (elements) are rendered correctly
     * @scenario Rendering Heading component with complex children (elements)
     * @expected Complex children (elements) are rendered correctly
     */
    it("renders complex children (elements)", () => {
      const child = <span>Inner span</span>;
      render(<Heading>{child}</Heading>);
      expect(screen.getByText("Inner span")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  /**
   * Tests passthrough of HTML attributes.
   * Covers React.HTMLAttributes spread.
   */
  describe("passes through HTML attributes", () => {
    /**
     * @description Verifies id attribute is applied correctly
     * @scenario Rendering Heading component with id="test-id"
     * @expected Heading has id="test-id"
     */
    it("applies id attribute", () => {
      const id = "test-id";
      render(<Heading id={id}>Test</Heading>);
      expect(screen.getByRole("heading")).toHaveAttribute("id", id);
    });

    /**
     * @description Verifies data-* attributes are passed through correctly
     * @scenario Rendering Heading component with data-testid="heading-test"
     * @expected Heading has data-testid="heading-test"
     */
    it("applies data-* attributes", () => {
      render(<Heading data-testid="heading-test">Test</Heading>);
      expect(screen.getByTestId("heading-test")).toBeInTheDocument();
    });

    /**
     * @description Verifies style attribute is applied correctly
     * @scenario Rendering Heading component with style={{ color: "red" }}
     * @expected Heading has style={{ color: "red" }}
     */
    it("applies style attribute", () => {
      const style = { color: "red" };
      render(<Heading style={style}>Test</Heading>);
      expect(screen.getByRole("heading")).toHaveStyle({ color: "red" });
    });

    /**
     * @description Verifies aria-label attribute is applied correctly
     * @scenario Rendering Heading component with aria-label="Test aria"
     * @expected Heading has aria-label="Test aria"
     */
    it("applies aria-label attribute", () => {
      const ariaLabel = "Test aria";
      render(<Heading aria-label={ariaLabel}>Test</Heading>);
      expect(screen.getByRole("heading")).toHaveAttribute(
        "aria-label",
        ariaLabel,
      );
    });
  });
});
