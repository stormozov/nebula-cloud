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
  ...props
}: PageWrapperProps) {
  const classes = classNames(
    "page__wrapper",
    `page__wrapper--direction-${direction}`,
    `page__wrapper--align-${align}`,
    `page__wrapper--justify-${justify}`,
    className,
  );
  return (
    <div {...props} className={classes}>
      {children}
    </div>
  );
}
