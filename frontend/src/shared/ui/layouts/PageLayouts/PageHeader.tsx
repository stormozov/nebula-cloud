import classNames from "classnames";

import "./PageLayouts.scss";

/**
 * Props for AppHeader component.
 */
interface AppHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
}

/**
 * App header layout component.
 */
export function AppHeader({ children, ...props }: AppHeaderProps) {
  return (
    <header {...props} className={classNames("page__header", props.className)}>
      {children}
    </header>
  );
}
