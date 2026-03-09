/**
 * Input types.
 */
export type InputType = "text" | "email" | "password" | "tel" | "number";

/**
 * Props for ControlledInput component.
 */
export interface IControlledInputProps
  extends Omit<
    React.InputHTMLAttributes<HTMLInputElement>,
    "onChange" | "value"
  > {
  /**
   * Input value (controlled component).
   */
  value: string;
  /**
   * Error message to display below the input.
   */
  error?: string;
  /**
   * Input label.
   */
  label?: string;
  /**
   * Input type (text, email, password, etc.).
   */
  type?: InputType;
  /**
   * Placeholder text.
   */
  placeholder?: string;
  /**
   * Disable the input.
   */
  disabled?: boolean;
  /**
   * Mark input as required.
   */
  required?: boolean;
  /**
   * Additional CSS class name.
   */
  className?: string;
  /**
   * Callback for value change.
   */
  onChange: (value: string) => void;
  /**
   * Callback for blur event.
   */
  onBlur?: () => void;
}
