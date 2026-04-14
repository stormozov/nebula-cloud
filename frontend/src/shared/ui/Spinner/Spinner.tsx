import classNames from "classnames";

import "./Spinner.scss";

/**
 * Represents the available sizes for the Spinner component.
 * ```
 */
export type SpinnerSize = "small" | "medium" | "large" | "xlarge";

/**
 * Represents the available color themes for the Spinner component.
 * ```
 */
export type SpinnerColor = "primary" | "secondary" | "tertiary";

/**
 * Props interface for the `Spinner` component.
 */
export interface ISpinnerProps {
  /** Optional size of the spinner. */
  size?: SpinnerSize;
  /** Optional color theme of the spinner. */
  color?: SpinnerColor;
  /** Optional text to display below the spinner. */
  text?: string;
}

/**
 * A loading spinner component with configurable size, color, and optional
 * accompanying text.
 *
 * @example
 * ```tsx
 * <Spinner />
 * <Spinner size="large" text="Loading data..." />
 * <Spinner color="secondary" size="xlarge" />
 * ```
 */
export function Spinner({
  size = "medium",
  color = "primary",
  text = "",
}: ISpinnerProps) {
  return (
    <div className="spinner">
      <div
        className={classNames("spinner__circle", {
          [`spinner__circle--${size}`]: size,
          [`spinner__circle--${color}`]: color,
        })}
        data-testid="spinner"
      />
      {text && <p className="spinner__text">{text}</p>}
    </div>
  );
}
