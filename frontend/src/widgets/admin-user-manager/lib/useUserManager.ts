import { useCallback, useEffect, useMemo, useState } from "react";

import { useGetUsersQuery } from "@/entities/user";
import { useUserSearch } from "@/features/admin";
import { useBodyScrollLock } from "@/shared/hooks";
import { useModalConfirm } from "@/shared/ui";

import type { IUseUserManagerReturns, SelectUser } from "./types";

/**
 * Hooks for managing users list and user details.
 */
export const useUserManager = (): IUseUserManagerReturns => {
  // -- States -----------------------------------------------------------------
  const [selectedUserId, setSelectedUserId] = useState<SelectUser>(null);
  const [pageState, setPageState] = useState(1);
  const [pendingAutoNavigateAfterLoad, setPendingAutoNavigateAfterLoad] =
    useState(false);
  const [pendingRefetch, setPendingRefetch] = useState(false);
  const [deletedUserIds, setDeletedUserIds] = useState(new Set<number>());

  // -- Hooks ------------------------------------------------------------------
  useBodyScrollLock(!!selectedUserId);

  const { searchTerm, setSearchTerm, debouncedSearchTerm } = useUserSearch();

  const { dialog, requestConfirm, handleConfirm, handleCancel } =
    useModalConfirm();

  // -- API --------------------------------------------------------------------
  const effectivePage = useMemo(() => {
    return debouncedSearchTerm ? 1 : pageState;
  }, [debouncedSearchTerm, pageState]);

  const queryArgs = useMemo(
    () => ({
      page: effectivePage,
      search: debouncedSearchTerm || undefined,
    }),
    [effectivePage, debouncedSearchTerm],
  );

  const {
    data: usersData,
    isLoading: usersLoading,
    error: usersError,
    refetch,
  } = useGetUsersQuery(queryArgs);

  // -- Consts -----------------------------------------------------------------
  const allUsers = useMemo(
    () => usersData?.results.filter((u) => !deletedUserIds.has(u.id)) ?? [],
    [usersData, deletedUserIds],
  );
  const totalCount = usersData?.count ?? 0;
  const hasMore = usersData?.next != null;

  const allUserIds = useMemo(() => allUsers.map((u) => u.id), [allUsers]);

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  const handleLoadMore = useCallback(() => {
    if (!hasMore || debouncedSearchTerm) return;
    setPageState((prev) => prev + 1);
  }, [hasMore, debouncedSearchTerm]);

  const handleRemoveUserLocally = useCallback(
    (userId: number) => {
      if (selectedUserId === userId) setSelectedUserId(null);
      setDeletedUserIds((prev) => new Set(prev).add(userId));
    },
    [selectedUserId],
  );

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  // The effect for executing a refetch after currentPage has actually become 1
  useEffect(() => {
    if (pendingRefetch && pageState === 1) {
      refetch();
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setPendingRefetch(false);
    }
  }, [pendingRefetch, pageState, refetch]);

  // Resetting the page when the search changes
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setPageState(1);
    setSelectedUserId(null);
    setPendingAutoNavigateAfterLoad(false);
    setPendingRefetch(false);
  }, []);

  // Automatically select the first user after the page loads
  useEffect(() => {
    if (!pendingAutoNavigateAfterLoad || allUsers.length === 0) return;
    const lastUser = allUsers[allUsers.length - 1];
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSelectedUserId(lastUser.id);
    setPendingAutoNavigateAfterLoad(false);
  }, [allUsers, pendingAutoNavigateAfterLoad]);

  // ---------------------------------------------------------------------------
  // RETURNS
  // ---------------------------------------------------------------------------

  return {
    // -- Data for users list --------------------------------------------------
    usersList: {
      items: allUsers,
      allIds: allUserIds,
      totalCount,
      hasMore,
      states: {
        isLoading: usersLoading,
        error: usersError,
        emptyMessage: "Пользователи не найдены",
      },
    },

    // -- Selected user --------------------------------------------------------
    selected: {
      userId: selectedUserId,
      setUserId: setSelectedUserId,
    },

    // -- Pagination and load more ---------------------------------------------
    pagination: {
      isLoadMoreLoading: usersLoading,
      loadMore: handleLoadMore,
    },

    // -- Search ---------------------------------------------------------------
    search: {
      term: searchTerm,
      debouncedTerm: debouncedSearchTerm,
      setTerm: setSearchTerm,
      onSearchChange: (value: string) => setSearchTerm(value),
    },

    // -- Confirm modal --------------------------------------------------------
    confirmModal: {
      isOpen: dialog.isOpen,
      title: dialog.title,
      message: dialog.message,
      requestConfirm,
      handleConfirm,
      handleCancel,
    },

    // -- User details modal ---------------------------------------------------
    userDetailsModal: {
      userId: selectedUserId,
      allUserIds,
      hasPaginationMore: hasMore,
      isConfirmOpen: dialog.isOpen,
      onLoadMore: handleLoadMore,
      onNavigate: setSelectedUserId,
      requestConfirm,
      onClose: () => setSelectedUserId(null),
      onUserDeleted: handleRemoveUserLocally,
    },
  };
};
