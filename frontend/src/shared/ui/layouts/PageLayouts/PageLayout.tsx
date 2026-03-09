import classNames from "classnames";

import { AppContainer } from "./PageContainer";
import { AppHeader } from "./PageHeader";
import { PageMain } from "./PageMain";
import { PageSidebar } from "./PageSidebar";

import "./PageLayouts.scss";

/**
 * Props for PageLayout component.
 */
interface IPageLayoutProps {
  children: React.ReactNode;
  className?: string;
}

/**
 * Page layout component that serves as a container for page content.
 *
 * Intended to wrap the main content of a page and can be extended
 * with additional layout elements if needed.
 */
function PageLayoutBase({ children, ...props }: IPageLayoutProps) {
  return (
    <div {...props} className={classNames("page", props.className)}>
      {children}
    </div>
  );
}

export const PageLayout = Object.assign(PageLayoutBase, {
  Header: AppHeader,
  Main: PageMain,
  Container: AppContainer,
  Sidebar: PageSidebar,
});
