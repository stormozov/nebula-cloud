import { Spinner } from "../Spinner";

import "./PageLoader.scss";

/**
 * A loading indicator component that displays a spinner and optional loading
 * text.
 *
 * Used to indicate that a page or section is currently loading.
 * The component renders a spinner and, if specified, a text message below it.
 */
export function PageLoader() {
  return (
    <div className="page-loader">
      <Spinner size="xlarge" text="Загрузка..." />
    </div>
  );
}
