import "./PageLayouts.scss";

/**
 * Props for PageContainer component.
 */
interface PageContainerProps {
  children: React.ReactNode;
}

/**
 * A layout component that wraps the main content of the application in a container.
 *
 * Provides consistent spacing, alignment, and max-width constraints across pages.
 * Used to center content and limit its maximum width for better readability and design consistency.
 */
export function AppContainer({ children }: PageContainerProps) {
  return <div className="page__container">{children}</div>;
}
