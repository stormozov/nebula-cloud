import "./PageLayouts.scss";

/**
 * Props for AppHeader component.
 */
interface AppHeaderProps {
  children: React.ReactNode;
}

/**
 * App header layout component.
 */
export function AppHeader({ children }: AppHeaderProps) {
  return <header className="page__header">{children}</header>;
}
