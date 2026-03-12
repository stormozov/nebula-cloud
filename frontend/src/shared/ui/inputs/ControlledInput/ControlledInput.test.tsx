import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ControlledInput } from "./ControlledInput";
import type { IControlledInputProps } from "./types";

describe("ControlledInput", () => {
  /**
   * Tests basic rendering and HTML structure.
   * Verifies input element, role, conditional label/error, generated IDs.
   */
  describe("renders correct input structure", () => {
    /**
     * @description Verifies default input renders as accessible textbox with type=text
     * @scenario Render ControlledInput with minimal props
     * @expected Input element exists with role= textbox, tag=input, type=text by default
     */
    it("renders input element with correct role and type=text by default", () => {
      render(<ControlledInput value="" onChange={vi.fn()} />);
      const input = screen.getByRole("textbox");
      expect(input).toBeInTheDocument();
      expect(input.tagName.toLowerCase()).toBe("input");
      expect(input).toHaveAttribute("type", "text");
    });

    /**
     * @description Tests conditional label rendering based on label prop
     * @scenario Render with label="Test Label" prop
     * @expected Label text "Test Label" appears in document
     */
    it("renders label when label prop provided", () => {
      render(
        <ControlledInput value="" onChange={vi.fn()} label="Test Label" />,
      );
      expect(screen.getByText("Test Label")).toBeInTheDocument();
    });

    /**
     * @description Verifies required state visual indicator with asterisk
     * @scenario Render with label="Required" and required=true
     * @expected Asterisk "*" character rendered in document
     */
    it("renders required asterisk when label and required=true", () => {
      render(
        <ControlledInput
          value=""
          onChange={vi.fn()}
          label="Required"
          required
        />,
      );
      expect(screen.getByText("*")).toBeInTheDocument();
    });

    /**
     * @description Tests error message display for validation feedback
     * @scenario Render with error="Test error" prop
     * @expected Error text "Test error" appears in document
     */
    it("renders error message when error prop provided", () => {
      const error = "Test error";
      render(<ControlledInput value="" onChange={vi.fn()} error={error} />);
      expect(screen.getByText(error)).toBeInTheDocument();
    });

    /**
     * @description Confirms label is conditionally omitted when not provided
     * @scenario Render without label prop
     * @expected No label element present in document
     */
    it("does not render label when label not provided", () => {
      render(<ControlledInput value="" onChange={vi.fn()} />);
      expect(screen.queryByRole("label")).not.toBeInTheDocument();
    });

    /**
     * @description Verifies error message is conditionally hidden when no error
     * @scenario Render without error prop
     * @expected No error alert role element in document
     */
    it("does not render error when error not provided", () => {
      render(<ControlledInput value="" onChange={vi.fn()} />);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });
  });

  // ===========================================================================

  /**
   * Tests CSS class construction exhaustively.
   * Covers classNames() logic, all modifiers, combinations, defaults.
   */
  describe("applies correct CSS classes", () => {
    /**
     * @description Verifies base CSS class application for component recognition
     * @scenario Default ControlledInput render without modifiers
     * @expected Container element has "controlled-input" base class
     */
    it("applies default classes: controlled-input", () => {
      render(<ControlledInput value="" onChange={vi.fn()} />);
      const container = screen
        .getByRole("textbox")
        .closest(".controlled-input");
      expect(container).toHaveClass("controlled-input");
    });

    /**
     * @description Tests error state CSS modifier class application
     * @scenario Render with error="Error" prop
     * @expected Container has "controlled-input--error" modifier class
     */
    it("applies controlled-input--error class when error exists", () => {
      render(<ControlledInput value="" onChange={vi.fn()} error="Error" />);
      const container = screen
        .getByRole("textbox")
        .closest(".controlled-input");
      expect(container).toHaveClass("controlled-input--error");
    });

    /**
     * @description Tests disabled state CSS modifier class application
     * @scenario Render with disabled=true prop
     * @expected Container has "controlled-input--disabled" modifier class
     */
    it("applies controlled-input--disabled class when disabled=true", () => {
      render(<ControlledInput value="" onChange={vi.fn()} disabled />);
      const container = screen
        .getByRole("textbox")
        .closest(".controlled-input");
      expect(container).toHaveClass("controlled-input--disabled");
    });

    /**
     * @description Verifies custom className prop integration with classNames utility
     * @scenario Render with className="my-custom" prop
     * @expected Container classList contains literal "my-custom" value
     */
    it("verifies className prop is appended as additional class", () => {
      render(
        <ControlledInput value="" onChange={vi.fn()} className="my-custom" />,
      );
      const container = screen
        .getByRole("textbox")
        .closest(".controlled-input");
      expect(container?.className).toContain("my-custom");
    });

    /**
     * @description Tests complete CSS class combination: modifiers + literal className
     * @scenario Render with error, disabled=true, className="className"
     * @expected All 4 classes: base + 2 modifiers + literal className
     */
    it("combines modifier classes with literal className correctly", () => {
      render(
        <ControlledInput
          value=""
          onChange={vi.fn()}
          error="Error"
          disabled
          className="className"
        />,
      );
      const container = screen
        .getByRole("textbox")
        .closest(".controlled-input");
      expect(container).toHaveClass("controlled-input");
      expect(container).toHaveClass("controlled-input--error");
      expect(container).toHaveClass("controlled-input--disabled");
      expect(container?.className).toContain("className");
    });

    /**
     * @description Ensures empty className="" doesn't break base classes
     * @scenario Render with className="" empty string
     * @expected Base "controlled-input" class still applied correctly
     */
    it("handles empty string className without breaking class list", () => {
      render(<ControlledInput value="" onChange={vi.fn()} className="" />);
      const container = screen
        .getByRole("textbox")
        .closest(".controlled-input");
      expect(container).toHaveClass("controlled-input");
    });
  });

  // ===========================================================================

  /**
   * Tests input value control and event handlers.
   * Covers controlled value prop, onChange, onBlur, placeholder.
   */
  describe("handles input value and events", () => {
    /**
     * @description Verifies controlled input displays value prop correctly
     * @scenario Render with value="test value" prop
     * @expected Input element value attribute matches prop exactly
     */
    it("renders controlled value correctly", () => {
      const value = "test value";
      render(<ControlledInput value={value} onChange={vi.fn()} />);
      expect(screen.getByRole("textbox")).toHaveValue(value);
    });

    /**
     * @description Tests user input updates trigger onChange callback
     * @scenario User types "new value" in empty input field
     * @expected onChange called once with exact typed value "new value"
     */
    it("calls onChange with new value when user types", () => {
      const handleChange = vi.fn();
      render(<ControlledInput value="" onChange={handleChange} />);
      const input = screen.getByRole("textbox");
      fireEvent.change(input, { target: { value: "new value" } });
      expect(handleChange).toHaveBeenCalledWith("new value");
    });

    /**
     * @description Verifies focus loss triggers onBlur callback correctly
     * @scenario Render with onBlur handler, trigger blur event on input
     * @expected onBlur callback called exactly once
     */
    it("calls onBlur when input loses focus", () => {
      const handleBlur = vi.fn();
      render(
        <ControlledInput value="" onChange={vi.fn()} onBlur={handleBlur} />,
      );
      const input = screen.getByRole("textbox");
      fireEvent.blur(input);
      expect(handleBlur).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Ensures missing onBlur prop doesn't cause runtime errors
     * @scenario Render without onBlur, fire blur event on input
     * @expected No exceptions thrown during blur event
     */
    it("handles missing onBlur prop without error", () => {
      render(<ControlledInput value="" onChange={vi.fn()} />);
      const input = screen.getByRole("textbox");
      expect(() => fireEvent.blur(input)).not.toThrow();
    });

    /**
     * @description Tests placeholder attribute with empty value state
     * @scenario Render empty value with placeholder="test placeholder"
     * @expected Input placeholder attribute set to provided text
     */
    it("renders placeholder when provided and value empty", () => {
      render(
        <ControlledInput
          value=""
          onChange={vi.fn()}
          placeholder="test placeholder"
        />,
      );
      expect(screen.getByRole("textbox")).toHaveAttribute(
        "placeholder",
        "test placeholder",
      );
    });

    /**
     * @description Verifies placeholder attribute with non-empty value
     * @scenario Render with value="filled" and placeholder prop
     * @expected Input value="filled", placeholder attribute still present
     */
    it("clears placeholder when value is not empty", () => {
      render(
        <ControlledInput
          value="filled"
          onChange={vi.fn()}
          placeholder="placeholder"
        />,
      );
      const input = screen.getByRole("textbox");
      expect(input).toHaveValue("filled");
      expect(input).toHaveAttribute("placeholder", "placeholder");
    });
  });

  // ===========================================================================

  /**
   * Tests all input types and required/disabled states.
   */
  describe("handles input states and types", () => {
    /**
     * @description Verifies all supported input types render correctly
     * @scenario Loop through text,email,password,tel,number types
     * @expected Each input has correct matching type attribute
     */
    const inputTypes: IControlledInputProps["type"][] = [
      "text",
      "email",
      "password",
      "tel",
      "number",
    ];

    inputTypes.forEach((type) => {
      /**
       * @description Tests specific ${type} input type attribute
       * @scenario Render ControlledInput type="${type}"
       * @expected Input element type attribute exactly matches "${type}"
       */
      it(`renders input with type="${type}" correctly`, () => {
        render(<ControlledInput value="" onChange={vi.fn()} type={type} />);
        const input = document.querySelector("input");
        expect(input).toHaveAttribute("type", type);
      });
    });

    /**
     * @description Verifies disabled input state with event handling
     * @scenario disabled=true input, fire synthetic change event
     * @expected Input has disabled attribute, onChange still fires (React)
     */
    it("applies disabled attribute correctly with events", () => {
      const handleChange = vi.fn();
      render(
        <ControlledInput value="initial" onChange={handleChange} disabled />,
      );
      const input = screen.getByRole("textbox");
      expect(input).toBeDisabled();
      fireEvent.change(input, { target: { value: "new" } });
      expect(handleChange).toHaveBeenCalledWith("new");
    });

    /**
     * @description Tests required HTML attribute passthrough
     * @scenario Render with required=true prop
     * @expected Input element has required attribute present
     */
    it("applies required attribute when required=true", () => {
      render(<ControlledInput value="" onChange={vi.fn()} required />);
      expect(screen.getByRole("textbox")).toHaveAttribute("required");
    });
  });

  // ===========================================================================

  /**
   * Tests accessibility attributes for error states.
   */
  describe("handles accessibility attributes", () => {
    /**
     * @description Verifies error state accessibility linking
     * @scenario Render with error message, check ARIA attributes
     * @expected aria-invalid=true, aria-describedby links to error ID
     */
    it("sets aria-invalid=true and aria-describedby when error exists", () => {
      render(
        <ControlledInput value="" onChange={vi.fn()} error="Error message" />,
      );
      const input = screen.getByRole("textbox");
      const error = screen.getByRole("alert");
      expect(input).toHaveAttribute("aria-invalid", "true");
      expect(input).toHaveAttribute(
        "aria-describedby",
        error.getAttribute("id"),
      );
    });

    /**
     * @description Confirms aria-invalid=false in valid state
     * @scenario Render without error prop
     * @expected aria-invalid="false", no aria-describedby
     */
    it("sets aria-invalid false when no error as per component", () => {
      render(<ControlledInput value="" onChange={vi.fn()} />);
      const input = screen.getByRole("textbox");
      expect(input).toHaveAttribute("aria-invalid", "false");
      expect(input).not.toHaveAttribute("aria-describedby");
    });

    /**
     * @description Tests label-input association via IDs
     * @scenario Render with label prop, verify label "for" matches input id
     * @expected Label for attribute exactly matches input ID attribute
     */
    it('uses label "for" attribute matching input id', () => {
      render(<ControlledInput value="" onChange={vi.fn()} label="Label" />);
      const label = screen.getByText("Label").closest("label");
      const inputId = screen.getByRole("textbox").getAttribute("id");
      expect(label).toHaveAttribute("for", inputId);
    });
  });

  // ===========================================================================

  /**
   * Tests HTML attribute passthrough and ref forwarding.
   */
  describe("passes through HTML attributes and forwards ref", () => {
    /**
     * @description Tests HTML id attribute passthrough to input
     * @scenario Render with id="test-input-id" prop
     * @expected Input element id attribute matches exactly
     */
    it("applies id attribute correctly", () => {
      const id = "test-input-id";
      render(<ControlledInput value="" onChange={vi.fn()} id={id} />);
      expect(screen.getByRole("textbox")).toHaveAttribute("id", id);
    });

    /**
     * @description Verifies data-* attribute passthrough support
     * @scenario Render with data-testid="input-test"
     * @expected Element queryable via data-testid selector
     */
    it("applies data-* attributes correctly", () => {
      render(
        <ControlledInput
          value=""
          onChange={vi.fn()}
          data-testid="input-test"
        />,
      );
      expect(screen.getByTestId("input-test")).toBeInTheDocument();
    });

    /**
     * @description Tests inline style prop passthrough to input
     * @scenario Render with style={borderColor: "red"}
     * @expected Input computed style borderColor=red
     */
    it("applies inline style correctly", () => {
      const style = { borderColor: "red" };
      render(<ControlledInput value="" onChange={vi.fn()} style={style} />);
      expect(screen.getByRole("textbox")).toHaveStyle({ borderColor: "red" });
    });

    /**
     * @description Verifies ref forwarding reaches native input element
     * @scenario Render with ref=vi.fn() callback ref
     * @expected Ref callback receives input DOM element
     */
    it("forwards ref to input element", () => {
      const ref = vi.fn();
      render(<ControlledInput ref={ref} value="" onChange={vi.fn()} />);
      expect(ref).toHaveBeenCalled();
      const input = screen.getByRole("textbox");
      expect(ref.mock.calls[0][0]).toBe(input);
    });
  });

  // ===========================================================================

  /**
   * Snapshot tests for visual regression across key configurations.
   */
  describe("snapshot tests", () => {
    /**
     * @description Snapshot test for default/minimal configuration
     * @scenario Render basic ControlledInput with value="default"
     * @expected Matches saved baseline snapshot
     */
    it("matches snapshot for default input", () => {
      const { container } = render(
        <ControlledInput value="default" onChange={vi.fn()} />,
      );
      expect(container.firstChild).toMatchSnapshot();
    });

    /**
     * @description Comprehensive snapshot with all major modifiers
     * @scenario Full props: label, error, disabled, required, password, className
     * @expected Matches saved complex configuration snapshot
     */
    it("matches snapshot for input with label, error, disabled", () => {
      const { container } = render(
        <ControlledInput
          value=""
          onChange={vi.fn()}
          label="Label"
          error="Error"
          disabled
          required
          type="password"
          className="test"
          placeholder="placeholder"
          id="snap-id"
        />,
      );
      expect(container.firstChild).toMatchSnapshot();
    });

    /**
     * @description Minimal snapshot without optional elements
     * @scenario Empty ControlledInput without label or error
     * @expected Matches saved minimal snapshot
     */
    it("matches snapshot for minimal input without label/error", () => {
      const { container } = render(
        <ControlledInput value="" onChange={vi.fn()} />,
      );
      expect(container.firstChild).toMatchSnapshot();
    });
  });
});
