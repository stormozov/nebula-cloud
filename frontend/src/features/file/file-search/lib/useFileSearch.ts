import { useEffect, useState } from "react";
import { useDebouncedCallback } from "use-debounce";

/**
 * Interface representing the return value of the `useFileSearch` hook.
 */
interface UseFileSearchReturns {
  /** The current search term entered by the user. */
  searchTerm: string;

  /**
   * The debounced version of the search term, updated after a delay to avoid
   * excessive processing.
   */
  debouncedSearchTerm: string;

  /** Function to update the search term. Accepts a string value. */
  setSearchTerm: (value: string) => void;

  /**
   * Function to reset both the current and debounced search terms to empty
   * strings.
   */
  resetSearch: () => void;
}

/**
 * Custom React hook for managing file search state with debounce functionality.
 *
 * This hook provides state and functions to handle user input in a search field,
 * including a debounced version of the search term to optimize performance
 * (e.g., for filtering or API calls). The debounce delay is set to 500ms.
 *
 * @example
 * const {
 *    searchTerm, debouncedSearchTerm, setSearchTerm, resetSearch
 * } = useFileSearch();
 *
 * <input value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
 * <button onClick={resetSearch}>Clear</button>
 *
 * // Use `debouncedSearchTerm` for filtering or API requests
 */
export const useFileSearch = (): UseFileSearchReturns => {
  const [searchTerm, setSearchTerm] = useState("");
  const [debouncedSearchTerm, setDebouncedSearchTerm] = useState("");

  const debounced = useDebouncedCallback((value: string) => {
    setDebouncedSearchTerm(value);
  }, 500);

  useEffect(() => {
    debounced(searchTerm);
  }, [searchTerm, debounced]);

  const resetSearch = () => {
    setSearchTerm("");
    setDebouncedSearchTerm("");
  };

  return {
    searchTerm,
    debouncedSearchTerm,
    setSearchTerm,
    resetSearch,
  };
};
