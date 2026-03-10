import classNames from "classnames";

import "./PageLayouts.scss";

/**
 * Props for PageMain component.
 */
interface PageMainProps {
  children: React.ReactNode;
  className?: string;
}

/**
 * A semantic main container component for the primary content of a page.
 *
 * This component renders a `<main>` HTML element with a base class and allows
 * additional classes and props to be passed through. It is intended to wrap
 * the central content of a page, providing consistent styling and structure.
 */
export function PageMain({ children, ...props }: PageMainProps) {
  return (
    <main {...props} className={classNames("page__main", props.className)}>
      {children}
    </main>
  );
}
