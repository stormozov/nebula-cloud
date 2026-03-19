import classNames from "classnames";
import { forwardRef, useId } from "react";

import type { IControlledTextareaProps } from "./types";

import "./ControlledTextarea.scss";

/**
 * Controlled textarea component.
 */
export const ControlledTextarea = forwardRef<
  HTMLTextAreaElement,
  IControlledTextareaProps
>(
  (
    {
      value,
      onChange,
      onBlur,
      error,
      label,
      placeholder,
      disabled = false,
      required = false,
      className,
      rows = 3,
      maxLength,
      ...restProps
    },
    ref,
  ) => {
    const textareaId = useId();
    const errorId = `${textareaId}-error`;

    const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
      onChange(event.target.value);
    };

    const textareaClasses = classNames(
      "controlled-textarea",
      {
        "controlled-textarea--error": !!error,
        "controlled-textarea--disabled": disabled,
      },
      className,
    );

    return (
      <div className={textareaClasses}>
        {label && (
          <label htmlFor={textareaId} className="controlled-textarea__label">
            {label}
            {required && (
              <span className="controlled-textarea__required">*</span>
            )}
          </label>
        )}

        <textarea
          ref={ref}
          id={textareaId}
          value={value}
          onChange={handleChange}
          onBlur={onBlur}
          placeholder={placeholder}
          disabled={disabled}
          required={required}
          rows={rows}
          maxLength={maxLength}
          aria-invalid={!!error}
          aria-describedby={error ? errorId : undefined}
          className="controlled-textarea__field"
          {...restProps}
        />

        {error && (
          <span
            id={errorId}
            className="controlled-textarea__error"
            role="alert"
          >
            {error}
          </span>
        )}
      </div>
    );
  },
);

ControlledTextarea.displayName = "ControlledTextarea";