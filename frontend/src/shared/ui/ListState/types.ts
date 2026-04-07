/**
 * Properties for the loading, error, and empty states.
 */
export interface IListStates {
  /** Optional flag indicating whether the file list is currently loading. */
  isLoading?: boolean;
  /** Optional error message to display when an error occurs. */
  error?: string | null | unknown;
  /** Optional message to display when the file list is empty. */
  emptyMessage?: string;
}

/**
 * Properties for custom rendering of loading, error, and empty states
 * for the ListState component.
 */
export interface IListStatesRenders {
  /** Optional function to render the loading state. */
  renderLoading?: () => React.ReactNode;
  /** Optional function to render the error state. */
  renderError?: (error: string) => React.ReactNode;
  /** Optional function to render the empty state. */
  renderEmpty?: (message: string) => React.ReactNode;
}
