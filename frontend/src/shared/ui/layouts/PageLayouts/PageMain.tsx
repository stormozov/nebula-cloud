import "./PageLayouts.scss";

/**
 * Props for PageMain component.
 */
interface PageMainProps {
  children: React.ReactNode;
}

export function PageMain({ children }: PageMainProps) {
  return <main className="page__main">{children}</main>;
}
