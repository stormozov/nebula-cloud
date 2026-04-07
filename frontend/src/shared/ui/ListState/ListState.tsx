import { Icon } from "../Icon";
import type { IListStates, IListStatesRenders } from "./types";

import "./ListState.scss";

/**
 * Properties for the ListState component.
 */
interface IListStateProps {
  /** The content to be rendered when states are not active. */
  children: React.ReactNode;
  /** Properties for the loading, error, and empty states. */
  states?: IListStates & { itemsCount?: number };
  /** Optional render functions for the loading, error, and empty states. */
  renders?: IListStatesRenders;
}

/**
 * A component that conditionally renders different UI states for a list:
 * loading, error, empty, or the actual content.
 *
 * This component abstracts the common logic of handling various asynchronous
 * states when displaying lists of data, providing fallbacks and customizable
 * rendering for each state.
 *
 * @example
 * <ListState
 *   states={{
 *     isLoading: false,
 *     error: null,
 *     emptyMessage: "No files uploaded",
 *     itemsCount: 0
 *   }}
 *   renders={{
 *     renderEmpty: (msg) => <EmptyState message={msg} />
 *   }}
 *   ...
 * >
 *   <FileList files={files} />
 * </ListState>
 */
export function ListState({ children, states, renders }: IListStateProps) {
  const { isLoading, error, emptyMessage, itemsCount } = states || {};
  const { renderLoading, renderError, renderEmpty } = renders || {};

  if (isLoading) {
    return (
      <div className="list-state list-state--loading" aria-live="polite">
        {renderLoading?.() ?? (
          <div className="list-state__default-block">
            <Icon
              name="cloudLoading"
              size={160}
              className="list-state__icon"
            />
            <p>Загрузка...</p>
          </div>
        )}
      </div>
    );
  }

  if (error && typeof error === "string") {
    return (
      <div className="list-state list-state--error" role="alert">
        {renderError?.(error) ?? (
          <div className="list-state__default-block">
            <Icon
              name="cloudWarning"
              size={160}
              className="list-state__icon"
            />
            <p>Произошла ошибка</p>
            <p>{error}</p>
          </div>
        )}
      </div>
    );
  }

  if (itemsCount === 0) {
    return (
      <div className="list-state list-state--empty">
        {renderEmpty?.(emptyMessage || "Ничего не найдено") ?? (
          <div className="list-state__default-block">
            <Icon
              name="cloudBad"
              size={160}
              className="list-state__icon"
            />
            <p>{emptyMessage}</p>
          </div>
        )}
      </div>
    );
  }

  return <>{children}</>;
}
