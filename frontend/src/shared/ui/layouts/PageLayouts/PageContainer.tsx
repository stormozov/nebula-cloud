import classNames from "classnames";

import "./PageLayouts.scss";

/**
 * Props for PageContainer component.
 */
interface PageContainerProps {
  children: React.ReactNode;
  className?: string;
}

/**
 * A layout component that wraps the main content of the application
 * in a container.
 */
export function AppContainer({ children, ...props }: PageContainerProps) {
  return (
    <div {...props} className={classNames("page__container", props.className)}>
      {children}
    </div>
  );
}
