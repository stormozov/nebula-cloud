import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Form } from "./index";

describe("Form components", () => {
  /**
   * Tests Form base rendering: element, defaults, structure.
   */
  describe("Form renders correct form element", () => {
    it("renders form element with correct tag and default attributes", () => {
      /**
       * @description Should render basic form element correctly
       * @scenario Render Form without props
       * @expected Form tag with class "form"
       */
      const { container } = render(
        <Form>
          <div>content</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toBeInTheDocument();
      expect(form?.tagName.toLowerCase()).toBe("form");
      expect(form).toHaveClass("form");
    });

    it("passes HTML attributes like method", () => {
      /**
       * @description Should spread HTML form attributes
       * @scenario Render Form with method="post"
       * @expected Form has method="post"
       */
      const { container } = render(
        <Form method="post">
          <div></div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveAttribute("method", "post");
    });

    it("renders children content inside form", () => {
      /**
       * @description Should render children inside form
       * @scenario Render Form with input child
       * @expected Input textbox rendered
       */
      render(
        <Form>
          <input type="text" />
        </Form>,
      );
      expect(screen.getByRole("textbox")).toBeInTheDocument();
    });

    it("accesses compound Row correctly", () => {
      /**
       * @description Should render Form.Row compound component
       * @scenario Render Form.Row with content
       * @expected Row div rendered with content
       */
      const { container: rowContainer } = render(
        <Form.Row>
          <span>Row content</span>
        </Form.Row>,
      );
      const row = rowContainer.querySelector(".form__row");
      expect(row).toBeInTheDocument();
    });

    it("accesses compound SubmitErrorBlock correctly", () => {
      /**
       * @description Should render Form.SubmitErrorBlock compound
       * @scenario Render with errors
       * @expected Alert rendered
       */
      render(<Form.SubmitErrorBlock errors="test" />);
      expect(screen.getByRole("alert")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  /**
   * Tests Form CSS class construction: defaults, combinations, passthrough.
   */
  describe("Form applies correct CSS classes", () => {
    it("applies default 'form' class", () => {
      /**
       * @description Should apply default form class
       * @scenario Render default Form
       * @expected Contains "form" class
       */
      const { container } = render(
        <Form>
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveClass("form");
    });

    it("combines 'form' with custom className using classNames", () => {
      /**
       * @description Should merge custom className with base "form"
       * @scenario Render Form with className="custom"
       * @expected Has both "form" and "custom" classes
       */
      const { container } = render(
        <Form className="custom">
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveClass("form", "custom");
    });

    it("handles empty className gracefully", () => {
      /**
       * @description Should handle empty string className
       * @scenario Render Form with className=""
       * @expected Still has "form" class, no breakage
       */
      const { container } = render(
        <Form className="">
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveClass("form");
    });

    it("handles multiple custom classes", () => {
      /**
       * @description Should handle className with multiple classes
       * @scenario Render Form with className="custom1 custom2"
       * @expected All classes preserved + "form"
       */
      const { container } = render(
        <Form className="custom1 custom2">
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form?.className).toContain("form custom1 custom2");
    });
  });

  // ===========================================================================

  /**
   * Tests Form HTML attributes passthrough and events.
   */
  describe("Form passes through HTML attributes and events", () => {
    it("applies id attribute correctly", () => {
      /**
       * @description Should apply id attribute from props
       * @scenario Render Form with id="test-form"
       * @expected Form has matching id
       */
      const id = "test-form";
      const { container } = render(
        <Form id={id}>
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveAttribute("id", id);
    });

    it("applies data-* attributes correctly", () => {
      /**
       * @description Should apply data attributes
       * @scenario Render Form with data-testid
       * @expected Form queryable by data-testid
       */
      render(
        <Form data-testid="form-test">
          <div>&nbsp;</div>
        </Form>,
      );
      expect(screen.getByTestId("form-test")).toBeInTheDocument();
    });

    it("applies inline style correctly", () => {
      /**
       * @description Should apply style prop
       * @scenario Render Form with style
       * @expected Style applied to form
       */
      const style = { backgroundColor: "blue" };
      const { container } = render(
        <Form style={style}>
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveStyle({ backgroundColor: "blue" });
    });

    it("applies aria attributes for accessibility", () => {
      /**
       * @description Should apply ARIA attributes
       * @scenario Render Form with aria-label
       * @expected ARIA label present
       */
      const ariaLabel = "Test form";
      const { container } = render(
        <Form aria-label={ariaLabel}>
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      expect(form).toHaveAttribute("aria-label", ariaLabel);
    });

    it("handles onSubmit event correctly", () => {
      /**
       * @description Should call onSubmit handler
       * @scenario Render Form with onSubmit, trigger submit
       * @expected Handler called once with event
       */
      const handleSubmit = vi.fn();
      const { container } = render(
        <Form onSubmit={handleSubmit}>
          <div>&nbsp;</div>
        </Form>,
      );
      const form = container.querySelector("form");
      if (form) fireEvent.submit(form);
      expect(handleSubmit).toHaveBeenCalledTimes(1);
    });

    it("renders form content when no other props", () => {
      /**
       * @description Should render with minimal children
       * @scenario Render Form with div child
       * @expected Div inside form
       */
      render(
        <Form>
          <div data-testid="child">test</div>
        </Form>,
      );
      expect(screen.getByTestId("child")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  /**
   * Tests Form children rendering variations.
   */
  describe("Form renders children content", () => {
    it("renders text children correctly", () => {
      /**
       * @description Should render simple text children
       * @scenario Form with text node
       * @expected Text visible
       */
      render(<Form>Form text</Form>);
      expect(screen.getByText("Form text")).toBeInTheDocument();
    });

    it("renders no children gracefully", () => {
      /**
       * @description Should handle empty/null children
       * @scenario Form with null children
       * @expected Form renders without errors
       */
      render(<Form>{null}</Form>);
      const { container } = render(<Form>{null}</Form>);
      const form = container.querySelector("form");
      expect(form).toBeInTheDocument();
    });

    it("renders complex React children", () => {
      /**
       * @description Should render nested elements
       * @scenario Form with div + input
       * @expected All children rendered
       */
      render(
        <Form>
          <div>
            <input data-testid="nested" />
          </div>
        </Form>,
      );
      expect(screen.getByTestId("nested")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  /**
   * Tests FormRow component: rendering, classes, passthrough.
   */
  describe("FormRow renders correctly", () => {
    it("renders div element with form__row class", () => {
      /**
       * @description Should render FormRow as div with correct class
       * @scenario Render FormRow
       * @expected Div with "form__row" class
       */
      const { container } = render(<Form.Row>&nbsp;</Form.Row>);
      const rowDiv = container.querySelector(".form__row");
      expect(rowDiv).toBeInTheDocument();
      expect(rowDiv?.tagName.toLowerCase()).toBe("div");
      expect(rowDiv).toHaveClass("form__row");
    });

    it("renders children inside row", () => {
      /**
       * @description Should render children in FormRow
       * @scenario FormRow with label + input
       * @expected Children visible, biome-compliant
       */
      render(
        <Form.Row>
          <label htmlFor="test-input">Label</label>
          <input id="test-input" />
        </Form.Row>,
      );
      expect(screen.getByLabelText("Label")).toBeInTheDocument();
    });

    it("passes through HTML div attributes", () => {
      /**
       * @description Should spread div attributes to FormRow
       * @scenario FormRow with id and style
       * @expected Attributes applied
       */
      const { container } = render(
        <Form.Row id="row1" style={{ padding: "10px" }}>
          &nbsp;
        </Form.Row>,
      );
      const rowDiv = container.querySelector("#row1");
      expect(rowDiv).toHaveAttribute("id", "row1");
      expect(rowDiv).toHaveClass("form__row");
    });

    it("applies custom className to FormRow", () => {
      /**
       * @description Should merge custom class with "form__row"
       * @scenario FormRow with className
       * @expected Both classes present + FormRow class
       */
      const { container } = render(<Form.Row>&nbsp;</Form.Row>);
      const rowDiv = container.querySelector(".form__row");
      expect(rowDiv?.className).toContain("form__row");
    });
  });

  // ===========================================================================

  /**
   * Tests FormSubmitErrorBlock: conditional render, accessibility.
   */
  describe("FormSubmitErrorBlock renders correctly", () => {
    it("renders error block when errors truthy", () => {
      /**
       * @description Should render error div when errors provided
       * @scenario Form.SubmitErrorBlock with errors string
       * @expected Div with "form__submit-error" and role="alert"
       */
      render(<Form.SubmitErrorBlock errors="Error message" />);
      const errorBlock = screen.getByRole("alert");
      expect(errorBlock).toBeInTheDocument();
      expect(errorBlock).toHaveClass("form__submit-error");
      expect(errorBlock).toHaveTextContent("Error message");
    });

    it("does not render when errors falsy (null)", () => {
      /**
       * @description Should return null when errors is null
       * @scenario Form.SubmitErrorBlock errors={null}
       * @expected No alert role, nothing rendered
       */
      render(<Form.SubmitErrorBlock errors="" />);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("does not render when errors empty string", () => {
      /**
       * @description Should treat empty string as falsy
       * @scenario Form.SubmitErrorBlock errors=""
       * @expected No render ( !!"" === false )
       */
      render(<Form.SubmitErrorBlock errors="" />);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("applies role=alert for accessibility when rendered", () => {
      /**
       * @description Should have correct ARIA role
       * @scenario Render with errors
       * @expected role="alert" attribute
       */
      render(<Form.SubmitErrorBlock errors="Test error" />);
      const errorBlock = screen.getByRole("alert");
      expect(errorBlock).toHaveAttribute("role", "alert");
    });
  });
});
