import "./PageLoader.scss";

/**
 * Props interface for the PageLoader component.
 */
interface IPageLoaderProps {
  /** Optional text to display below the loading spinner. */
  text?: string;
}

/**
 * A loading indicator component that displays a spinner and optional loading
 * text.
 *
 * Used to indicate that a page or section is currently loading.
 * The component renders a spinner and, if specified, a text message below it.
 */
export function PageLoader({ text = "Загрузка..." }: IPageLoaderProps) {
  return (
    <div className="page-loader">
      <div className="page-loader__spinner" />
      {text && <p className="page-loader__text">{text}</p>}
    </div>
  );
}
