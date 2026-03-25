import classNames from "classnames";
import type React from "react";

import "./Heading.scss";

export type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;
export type HeadingVariant =
  | "primary"
  | "secondary"
  | "tertiary"
  | "inverse"
  | "link"
  | "accent";
export type HeadingAlign = "left" | "center" | "right";
export type HeadingSize = "sm" | "md" | "lg" | "xl" | "2xl";

/**
 * Props for Heading component.
 */
export interface HeadingProps extends React.HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode;
  level?: HeadingLevel; // Select heading level (h1-h6)
  variant?: HeadingVariant; // Color variants
  align?: HeadingAlign; // Alignment
  size?: HeadingSize; // Visual size
}

/**
 * A constant object that maps heading levels (1-6) to their corresponding HTML
 * heading tags.
 */
const HEADING_TAGS = {
  1: "h1" as const,
  2: "h2" as const,
  3: "h3" as const,
  4: "h4" as const,
  5: "h5" as const,
  6: "h6" as const,
} as const;

/**
 * A customizable heading component that renders an HTML heading element (h1-h6)
 * with various styling options including variant, alignment, and size.
 *
 * @example
 * <Heading level={2} variant="secondary" align="center" size="lg">
 *   Page Title
 * </Heading>
 */
export function Heading({
  children,
  level = 1,
  variant = "primary",
  align = "left",
  size,
  className = "",
  ...props
}: HeadingProps) {
  const Tag = HEADING_TAGS[level];

  const classes = classNames(
    "heading",
    `heading--${variant}`,
    `heading--${align}`,
    {
      "heading--size": size === "sm",
    },
    className,
  );

  return (
    <Tag className={classes} {...props}>
      {children}
    </Tag>
  );
}
