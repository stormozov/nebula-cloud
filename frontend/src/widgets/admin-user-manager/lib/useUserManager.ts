import { useEffect, useState } from "react";

import { type IUserListResponse, useGetUsersQuery } from "@/entities/user";
import { useUserSearch } from "@/features/admin";
import { useModalConfirm } from "@/shared/ui";

/**
 * Hooks for managing users list and user details.
 */
export const useUserManager = () => {
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [loadedUsers, setLoadedUsers] = useState<IUserListResponse[]>([]);
  const [pendingAutoNavigateAfterLoad, setPendingAutoNavigateAfterLoad] =
    useState(false);

  const { searchTerm, setSearchTerm, debouncedSearchTerm } = useUserSearch();

  const {
    data: users,
    isLoading: usersLoading,
    error: usersError,
  } = useGetUsersQuery({
    page: currentPage,
    search: debouncedSearchTerm || undefined,
  });

  const { dialog, requestConfirm, handleConfirm, handleCancel } =
    useModalConfirm();

  const allUserIds = loadedUsers.map((user) => user.id) ?? [];

  const handleLoadMore = (shouldAutoNavigate: boolean = false) => {
    setPendingAutoNavigateAfterLoad(shouldAutoNavigate);
    setCurrentPage((prev) => prev + 1);
  };

  const handleSearchChange = (value: string) => {
    setSearchTerm(value);
    setCurrentPage(1);
    setSelectedUserId(null);
    setPendingAutoNavigateAfterLoad(false);
  };

  useEffect(() => {
    if (!users) return;

    if (currentPage === 1) {
      setTimeout(() => {
        setLoadedUsers(users.results);
        setPendingAutoNavigateAfterLoad(false);
      }, 0);
    } else {
      setTimeout(() => {
        setLoadedUsers((prev) => {
          const existingIds = new Set(prev.map((user) => user.id));
          const newUsers = users.results.filter(
            (user) => !existingIds.has(user.id),
          );
          if (pendingAutoNavigateAfterLoad && newUsers.length > 0) {
            setTimeout(() => {
              setSelectedUserId(newUsers[0].id);
              setPendingAutoNavigateAfterLoad(false);
            }, 0);
          }
          return [...prev, ...newUsers];
        });
      }, 0);
    }
  }, [users, currentPage, pendingAutoNavigateAfterLoad]);

  return {
    // Data for users list
    usersList: {
      items: loadedUsers,
      allIds: allUserIds,
      totalCount: users?.count ?? 0,
      hasMore: users?.next != null,
      isLoading: usersLoading,
      error: usersError,
    },

    // Selected user
    selected: {
      userId: selectedUserId,
      setUserId: setSelectedUserId,
    },

    // Pagination and load more
    pagination: {
      isLoadMoreLoading: usersLoading,
      loadMore: handleLoadMore,
    },

    // Search
    search: {
      term: searchTerm,
      debouncedTerm: debouncedSearchTerm,
      setTerm: setSearchTerm,
      onSearchChange: handleSearchChange,
    },

    // Confirm modal
    confirmModal: {
      isOpen: dialog.isOpen,
      title: dialog.title,
      message: dialog.message,
      requestConfirm,
      handleConfirm,
      handleCancel,
    },

    // User details modal
    userDetailsModal: {
      userId: selectedUserId,
      allUserIds,
      hasPaginationMore: users?.next != null,
      isConfirmOpen: dialog.isOpen,
      onLoadMore: handleLoadMore,
      onNavigate: setSelectedUserId,
      requestConfirm,
      onClose: () => setSelectedUserId(null),
    }
  };
};
