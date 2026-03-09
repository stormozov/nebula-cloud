import classNames from "classnames";
import { forwardRef, useId } from "react";

import type { IControlledInputProps } from "./types";

import "./ControlledInput.scss";

/**
 * Controlled input component with validation error display.
 * Used in forms for login, registration, and other user inputs.
 *
 * @param {IControlledInputProps} props - Component props
 * @param {string} props.value - Input value (controlled)
 * @param {(value: string) => void} props.onChange - Change callback
 * @param {() => void} props.onBlur - Blur callback (optional)
 * @param {string} props.error - Error message to display (optional)
 * @param {string} props.label - Input label (optional)
 * @param {InputType} props.type - Input type (optional, default: 'text')
 * @param {string} props.placeholder - Placeholder text (optional)
 * @param {boolean} props.disabled - Disable input (optional)
 * @param {boolean} props.required - Mark as required (optional)
 * @param {string} props.className - Additional CSS class (optional)
 * @param {React.Ref<HTMLInputElement>} ref - Forwarded ref
 *
 * @returns {JSX.Element} Controlled input component
 *
 * @example
 * <ControlledInput
 *   value={username}
 *   onChange={setUsername}
 *   error={errors.username}
 *   label="Username"
 *   placeholder="Enter your username"
 * />
 */
export const ControlledInput = forwardRef<
  HTMLInputElement,
  IControlledInputProps
>(
  (
    {
      value,
      onChange,
      onBlur,
      error,
      label,
      type = "text",
      placeholder,
      disabled = false,
      required = false,
      className,
      ...restProps
    },
    ref,
  ) => {
    const inputId = useId();
    const errorId = `${inputId}-error`;

    const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
      onChange(event.target.value);
    };

    const inputClasses = classNames("controlled-input", {
      "controlled-input--error": !!error,
      "controlled-input--disabled": disabled,
      className,
    });

    return (
      <div className={inputClasses}>
        {label && (
          <label htmlFor={inputId} className="controlled-input__label">
            {label}
            {required && <span className="controlled-input__required">*</span>}
          </label>
        )}

        <input
          ref={ref}
          id={inputId}
          type={type}
          value={value}
          onChange={handleChange}
          onBlur={onBlur}
          placeholder={placeholder}
          disabled={disabled}
          required={required}
          aria-invalid={!!error}
          aria-describedby={error ? errorId : undefined}
          className="controlled-input__field"
          {...restProps}
        />

        {error && (
          <span id={errorId} className="controlled-input__error" role="alert">
            {error}
          </span>
        )}
      </div>
    );
  },
);

ControlledInput.displayName = "ControlledInput";
