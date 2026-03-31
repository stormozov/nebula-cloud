import { useEffect, useState } from "react";
import { useDebouncedCallback } from "use-debounce";

/**
 * The return type of the `useUserSearch` hook.
 */
interface UseUserSearchReturns {
  searchTerm: string;
  debouncedSearchTerm: string;
  setSearchTerm: (value: string) => void;
  resetSearch: () => void;
}

/**
 * Custom hook for managing user search state with debouncing.
 *
 * This hook provides state for an input field and a debounced version of its
 * value, commonly used to avoid excessive API requests while typing.
 * The debounce delay is set to 500ms.
 */
export const useUserSearch = (): UseUserSearchReturns => {
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
