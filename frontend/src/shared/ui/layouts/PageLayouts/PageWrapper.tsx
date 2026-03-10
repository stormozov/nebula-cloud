import classNames from "classnames";

/**
 * Props for PageWrapper component.
 */
interface PageWrapperProps {
  children: React.ReactNode;
  className?: string;
}

/**
 * A semantic wrapper component for the page content.
 */
export function PageWrapper({ children, ...props }: PageWrapperProps) {
  return (
    <div {...props} className={classNames("page__wrapper", props.className)}>
      {children}
    </div>
  );
}
