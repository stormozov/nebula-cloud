import classNames from "classnames";

import { Logo, Navigation } from "@/shared/ui";
import { UserProfileMenu } from "@/widgets/user-profile-menu";

import "./PageLayouts.scss";

/**
 * Props interface for the `AppHeader` component.
 */
interface AppHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  /**
   * Optional content to render inside the header.
   *
   * If provided, this content will be used instead of the default header layout.
   */
  children?: React.ReactNode;
  /**
   * Optional CSS class name to apply custom styling to the header element.
   */
  className?: string;
}

/**
 * The application header component.
 *
 * Renders a header element with either custom `children` content or a default
 * layout.
 */
export function AppHeader({ children, ...props }: AppHeaderProps) {
  if (children) {
    return (
      <header
        {...props}
        className={classNames("page__header", props.className)}
      >
        {children}
      </header>
    );
  }

  return (
    <header {...props} className={classNames("page__header", props.className)}>
      <div className="page__header-container">
        <div className="page__header-content">
          <Logo />
          <Navigation />
          <UserProfileMenu />
        </div>
      </div>
    </header>
  );
}
