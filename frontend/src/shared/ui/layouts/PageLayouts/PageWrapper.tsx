import classNames from "classnames";

/**
 * Props for PageWrapper component.
 */
interface PageWrapperProps {
  children: React.ReactNode;
  className?: string;
  direction?: "row" | "column";
  align?: "start" | "center" | "end";
  justify?: "start" | "center" | "end" | "space-between";
  gap?: number | string;
  fullWidth?: boolean;
}

/**
 * A semantic wrapper component for the page content.
 */
export function PageWrapper({
  children,
  className,
  direction = "row",
  align = "start",
  justify = "start",
  gap,
  fullWidth,
  ...props
}: PageWrapperProps) {
  const classes = classNames(
    "page__wrapper",
    `page__wrapper--direction-${direction}`,
    `page__wrapper--align-${align}`,
    `page__wrapper--justify-${justify}`,
    {
      "full-width": fullWidth,
    },
    className,
  );
  return (
    <div {...props} style={{ gap }} className={classes}>
      {children}
    </div>
  );
}
