import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ControlledTextarea } from "./ControlledTextarea";
import type { IControlledTextareaProps } from "./types";

describe("ControlledTextarea", () => {
  const defaultProps: IControlledTextareaProps = {
    value: "",
    onChange: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  /**
   * @description Should render textarea with default attributes
   * @scenario Render component without optional props
   * @expected Textarea is present, not disabled, not required, rows=3, no error
   * styles
   */
  it("should render textarea with default attributes", () => {
    render(<ControlledTextarea {...defaultProps} />);
    const textarea = screen.getByRole("textbox");

    expect(textarea).toBeInTheDocument();
    expect(textarea).toHaveValue("");
    expect(textarea).not.toBeDisabled();
    expect(textarea).not.toHaveAttribute("required");
    expect(textarea).not.toHaveAttribute("maxlength");
    expect(textarea).toHaveAttribute("rows", "3");

    const wrapper = textarea.closest(".controlled-textarea");
    expect(wrapper).toBeInTheDocument();
    expect(wrapper).not.toHaveClass("controlled-textarea--error");
    expect(wrapper).not.toHaveClass("controlled-textarea--disabled");
  });

  /**
   * @description Should render label when provided
   * @scenario Pass label prop
   * @expected Label is displayed and associated with textarea via htmlFor
   */
  it("should render label when provided", () => {
    const labelText = "Description";
    render(<ControlledTextarea {...defaultProps} label={labelText} />);

    const label = screen.getByText(labelText);
    expect(label).toBeInTheDocument();

    const textarea = screen.getByRole("textbox");
    const textareaId = textarea.getAttribute("id");
    expect(label).toHaveAttribute("for", textareaId);
  });

  /**
   * @description Should show required asterisk when required prop is true
   * @scenario Set required={true} and provide label
   * @expected Asterisk symbol appears next to label
   */
  it("should show required asterisk when required prop is true", () => {
    const labelText = "Description";
    render(
      <ControlledTextarea
        {...defaultProps}
        label={labelText}
        required={true}
      />,
    );

    const asterisk = screen.getByText("*");
    expect(asterisk).toBeInTheDocument();
    expect(asterisk).toHaveClass("controlled-textarea__required");
  });

  /**
   * @description Should apply disabled attribute and styling when disabled
   * @scenario Set disabled={true}
   * @expected Textarea is disabled, wrapper has disabled class
   */
  it("should apply disabled attribute and styling when disabled", () => {
    render(<ControlledTextarea {...defaultProps} disabled={true} />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).toBeDisabled();

    const wrapper = textarea.closest(".controlled-textarea");
    expect(wrapper).toHaveClass("controlled-textarea--disabled");
  });

  /**
   * @description Should apply required attribute when required
   * @scenario Set required={true}
   * @expected Textarea has required attribute
   */
  it("should apply required attribute when required", () => {
    render(<ControlledTextarea {...defaultProps} required={true} />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveAttribute("required");
  });

  /**
   * @description Should apply maxLength attribute when provided
   * @scenario Set maxLength={100}
   * @expected Textarea has maxlength="100"
   */
  it("should apply maxLength attribute when provided", () => {
    render(<ControlledTextarea {...defaultProps} maxLength={100} />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveAttribute("maxlength", "100");
  });

  /**
   * @description Should apply rows attribute when provided
   * @scenario Set rows={5}
   * @expected Textarea has rows="5"
   */
  it("should apply rows attribute when provided", () => {
    render(<ControlledTextarea {...defaultProps} rows={5} />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveAttribute("rows", "5");
  });

  /**
   * @description Should merge custom className with default classes
   * @scenario Pass className="custom-class"
   * @expected Wrapper has both "controlled-textarea" and "custom-class"
   */
  it("should merge custom className with default classes", () => {
    render(<ControlledTextarea {...defaultProps} className="custom-class" />);

    const wrapper = screen.getByRole("textbox").closest(".controlled-textarea");
    expect(wrapper).toHaveClass("controlled-textarea");
    expect(wrapper).toHaveClass("custom-class");
  });

  /**
   * @description Should pass additional props to the textarea element
   * @scenario Pass placeholder and data-testid
   * @expected Textarea gets these attributes
   */
  it("should pass additional props to the textarea element", () => {
    render(
      <ControlledTextarea
        {...defaultProps}
        placeholder="Enter text"
        data-testid="my-textarea"
      />,
    );

    const textarea = screen.getByTestId("my-textarea");
    expect(textarea).toBeInTheDocument();
    expect(textarea).toHaveAttribute("placeholder", "Enter text");
  });

  /**
   * @description Should show error message and error styling when error prop
   * provided
   * @scenario Pass error="This field is required"
   * @expected Error message displayed, aria-invalid true, wrapper has error
   * class, textarea described by error
   */
  it("should show error message and error styling when error prop provided", () => {
    const errorMessage = "This field is required";
    render(<ControlledTextarea {...defaultProps} error={errorMessage} />);

    const errorSpan = screen.getByText(errorMessage);
    expect(errorSpan).toBeInTheDocument();
    expect(errorSpan).toHaveClass("controlled-textarea__error");
    expect(errorSpan).toHaveAttribute("role", "alert");

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveAttribute("aria-invalid", "true");

    const errorId = errorSpan.getAttribute("id");
    expect(textarea).toHaveAttribute("aria-describedby", errorId);

    const wrapper = textarea.closest(".controlled-textarea");
    expect(wrapper).toHaveClass("controlled-textarea--error");
  });

  /**
   * @description Should not set aria-describedby when error is absent
   * @scenario Render without error
   * @expected Textarea lacks aria-describedby attribute
   */
  it("should not set aria-describedby when error is absent", () => {
    render(<ControlledTextarea {...defaultProps} />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).not.toHaveAttribute("aria-describedby");
  });

  /**
   * @description Should call onChange with new value when user types
   * @scenario Type "hello" into textarea while using state to manage value
   * @expected onChange called with the accumulated string after each character,
   * last call with "hello"
   */
  it("should call onChange with new value when user types", async () => {
    const user = userEvent.setup();
    const onChangeSpy = vi.fn();

    const Wrapper = () => {
      const [value, setValue] = React.useState("");
      const handleChange = (newValue: string) => {
        onChangeSpy(newValue);
        setValue(newValue);
      };
      return <ControlledTextarea value={value} onChange={handleChange} />;
    };

    render(<Wrapper />);
    const textarea = screen.getByRole("textbox");
    await user.type(textarea, "hello");

    expect(onChangeSpy).toHaveBeenCalledTimes(5);
    expect(onChangeSpy).toHaveBeenLastCalledWith("hello");
    expect(onChangeSpy).toHaveBeenNthCalledWith(1, "h");
    expect(onChangeSpy).toHaveBeenNthCalledWith(2, "he");
    expect(onChangeSpy).toHaveBeenNthCalledWith(3, "hel");
    expect(onChangeSpy).toHaveBeenNthCalledWith(4, "hell");
    expect(onChangeSpy).toHaveBeenNthCalledWith(5, "hello");
  });

  /**
   * @description Should call onBlur when textarea loses focus
   * @scenario Focus and blur textarea
   * @expected onBlur called once
   */
  it("should call onBlur when textarea loses focus", async () => {
    const user = userEvent.setup();
    const onBlur = vi.fn();
    render(<ControlledTextarea {...defaultProps} onBlur={onBlur} />);

    const textarea = screen.getByRole("textbox");
    await user.click(textarea);
    await user.tab(); // move focus away

    expect(onBlur).toHaveBeenCalledTimes(1);
  });

  /**
   * @description Should forward ref to the underlying textarea element
   * @scenario Create a ref and pass it to component
   * @expected ref.current points to the textarea DOM node
   */
  it("should forward ref to the underlying textarea element", () => {
    const ref = React.createRef<HTMLTextAreaElement>();
    render(<ControlledTextarea {...defaultProps} ref={ref} />);

    expect(ref.current).toBeInstanceOf(HTMLTextAreaElement);
    expect(ref.current).toBe(screen.getByRole("textbox"));
  });

  /**
   * @description Should generate unique IDs for label association and error
   * description
   * @scenario Render component with label and error
   * @expected textarea id matches label's htmlFor, error id matches textarea's
   * aria-describedby
   */
  it("should generate unique IDs for label association and error description", () => {
    const labelText = "Comment";
    const errorText = "Error";
    render(
      <ControlledTextarea
        {...defaultProps}
        label={labelText}
        error={errorText}
      />,
    );

    const textarea = screen.getByRole("textbox");
    const textareaId = textarea.getAttribute("id");
    expect(textareaId).toBeTruthy();

    const label = screen.getByText(labelText);
    expect(label).toHaveAttribute("for", textareaId);

    const errorSpan = screen.getByText(errorText);
    const errorId = errorSpan.getAttribute("id");
    expect(errorId).toBeTruthy();
    expect(textarea).toHaveAttribute("aria-describedby", errorId);
  });

  /**
   * @description Should update displayed value when value prop changes
   * @scenario Render with initial value, then update via prop change
   * @expected Textarea value reflects new prop
   */
  it("should update displayed value when value prop changes", () => {
    const { rerender } = render(
      <ControlledTextarea {...defaultProps} value="initial" />,
    );

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveValue("initial");

    rerender(<ControlledTextarea {...defaultProps} value="updated" />);
    expect(textarea).toHaveValue("updated");
  });

  /**
   * @description Should not render label when label prop is omitted
   * @scenario Render without label
   * @expected No label element in document
   */
  it("should not render label when label prop is omitted", () => {
    render(<ControlledTextarea {...defaultProps} />);
    const label = document.querySelector(".controlled-textarea__label");
    expect(label).not.toBeInTheDocument();
  });

  /**
   * @description Should not render error message when error prop is omitted
   * @scenario Render without error
   * @expected No error span
   */
  it("should not render error message when error prop is omitted", () => {
    render(<ControlledTextarea {...defaultProps} />);

    const errorSpan = document.querySelector(".controlled-textarea__error");
    expect(errorSpan).not.toBeInTheDocument();
  });

  /**
   * @description Should set aria-invalid false when error is absent
   * @scenario Render without error
   * @expected Textarea aria-invalid is false or absent (spec says false)
   */
  it("should set aria-invalid false when error is absent", () => {
    render(<ControlledTextarea {...defaultProps} />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveAttribute("aria-invalid", "false");
  });
});
