import { useCallback, useEffect, useMemo, useRef, useState } from "react";

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
  /** Indicates whether the data is fully loaded. */
  isDataReady: boolean;
  /** Number of files on the current page. */
  currentPageFilesCount: number;
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
  const [pendingRefetch, setPendingRefetch] = useState(false);

  const prevArgsRef = useRef({ userId, searchTerm });

  const queryParams = useMemo(
    () => ({
      page: currentPage,
      search: searchTerm || undefined,
      ...(userId ? { userId } : {}),
    }),
    [currentPage, searchTerm, userId],
  );

  const { data, isLoading, error, isFetching, refetch } =
    useGetFilesQuery(queryParams);

  const files = data?.results ?? [];
  const hasNextPage = !!data?.next;
  const isDataReady = !!data?.results;
  const currentPageFilesCount = data?.results?.length ?? 0;
  const isInitialLoading = isLoading && currentPage === 1;

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  const loadMore = useCallback(() => setCurrentPage((prev) => prev + 1), []);

  const resetPagination = useCallback(() => {
    setCurrentPage(1);
    setPendingRefetch(true);
  }, []);

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (pendingRefetch && currentPage === 1) {
      refetch();
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setPendingRefetch(false);
    }
  }, [pendingRefetch, currentPage, refetch]);

  useEffect(() => {
    if (
      prevArgsRef.current.userId !== userId ||
      prevArgsRef.current.searchTerm !== searchTerm
    ) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCurrentPage(1);
      prevArgsRef.current = { userId, searchTerm };
    }
  }, [userId, searchTerm]);

  // ---------------------------------------------------------------------------
  // RETURNS
  // ---------------------------------------------------------------------------

  return {
    files,
    isLoading: isInitialLoading,
    isFetching,
    error,
    hasNextPage,
    isDataReady,
    currentPageFilesCount,
    loadMore,
    resetPagination,
  };
};
