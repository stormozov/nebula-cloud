import { useCallback, useEffect, useState } from "react";

import type { IFile } from "@/entities/file";
import { useGetFilesQuery } from "@/entities/file";

/**
 * Parameters for the `useFileManagerPagination` hook.
 */
interface IUseFileManagerPaginationParams {
  /** Optional user ID for searching files by owner. */
  userId?: number;
  /** Search term for filtering files by name or upload date. */
  searchTerm: string;
}

/**
 * Return value interface for the useFileManagerPagination hook.
 */
interface IUseFileManagerPaginationReturns {
  /** Array of file objects currently loaded and displayed. */
  files: IFile[];
  /** Indicates whether the initial data loading is in progress. */
  isLoading: boolean;
  /** Indicates whether additional data is being fetched. */
  isFetching: boolean;
  /** Error object if the request failed, or null if no error occurred. */
  error: unknown;
  /** Indicates whether more pages of data are available. */
  hasNextPage: boolean;
  /** Function to load the next page of files. */
  loadMore: () => void;
  /** Function to reset the pagination state. */
  resetPagination: () => void;
}

/**
 * Custom hook for managing pagination in the file manager.
 *
 * Handles loading, displaying, and navigating through pages of files with
 * support for filtering by user ID and search term. Manages the state for
 * infinite scrolling or pagination controls and deduplicates files when loading
 * additional pages.
 */
export const useFileManagerPagination = ({
  userId,
  searchTerm,
}: IUseFileManagerPaginationParams): IUseFileManagerPaginationReturns => {
  const [currentPage, setCurrentPage] = useState(1);
  const [loadedFiles, setLoadedFiles] = useState<IFile[]>([]);

  const queryParams = {
    page: currentPage,
    search: searchTerm || undefined,
    ...(userId ? { userId } : {}),
  };

  const { data, isLoading, error, isFetching } = useGetFilesQuery(queryParams);

  const hasNextPage = !!data?.next;

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  const loadMore = useCallback(() => {
    setCurrentPage((prev) => prev + 1);
  }, []);

  const resetPagination = useCallback(() => {
    setCurrentPage(1);
    setLoadedFiles([]);
  }, []);

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  // Update the list of files when the data changes.
  useEffect(() => {
    if (!data) return;

    if (currentPage === 1) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setLoadedFiles(data.results);
    } else {
      setLoadedFiles((prev) => {
        const existingIds = new Set(prev.map((f) => f.id));
        const newFiles = data.results.filter((f) => !existingIds.has(f.id));
        return [...prev, ...newFiles];
      });
    }
  }, [data, currentPage]);

  // Reset pagination when the userId or search query is changed
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    resetPagination();
  }, [resetPagination]);

  // ---------------------------------------------------------------------------
  // RETURNS
  // ---------------------------------------------------------------------------

  return {
    files: loadedFiles,
    isLoading,
    isFetching,
    error,
    hasNextPage,
    loadMore,
    resetPagination,
  };
};
