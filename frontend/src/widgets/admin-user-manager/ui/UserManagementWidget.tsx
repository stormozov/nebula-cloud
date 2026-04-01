import { useEffect, useState } from "react";

import { type IUserListResponse, useGetUsersQuery } from "@/entities/user";
import {
  UserDetailsModal,
  UserList,
  UserSearchInput,
  useUserSearch,
} from "@/features/admin";
import { Button, Icon, ModalConfirm, useModalConfirm } from "@/shared/ui";

import "./UserManagementWidget.scss";

export function UserManagementWidget() {
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

  // Обработка полученных данных
  useEffect(() => {
    if (!users) return;

    if (currentPage === 1) {
      setTimeout(() => {
        setLoadedUsers(users.results);
        setPendingAutoNavigateAfterLoad(false);
      });
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

  return (
    <div className="users-management w-full">
      <header className="users-management__header">
        <UserSearchInput
          buttonProps={{
            children: "Поиск",
            size: "small",
          }}
          inputProps={{
            value: searchTerm,
            className: "users-management__search",
            placeholder: "Поиск по ID, логину или email",
            onChange: handleSearchChange,
          }}
        />
        <div className="users-management__count">
          Всего пользователей: {users?.count ?? 0}
        </div>
      </header>

      <UserList
        users={loadedUsers}
        isLoading={usersLoading}
        error={usersError}
        onSelectUser={setSelectedUserId}
      />
      {users?.next && (
        <div className="users-management__load-more">
          <Button
            loading={usersLoading}
            disabled={usersLoading}
            onClick={() => handleLoadMore(false)}
          >
            <Icon name="retry" />
            Загрузить еще
          </Button>
        </div>
      )}

      {selectedUserId && (
        <UserDetailsModal
          userId={selectedUserId}
          allUserIds={allUserIds}
          hasPaginationMore={users?.next != null}
          onLoadMore={handleLoadMore}
          isConfirmOpen={dialog.isOpen}
          onNavigate={setSelectedUserId}
          requestConfirm={requestConfirm}
          onClose={() => setSelectedUserId(null)}
        />
      )}

      <ModalConfirm
        isOpen={dialog.isOpen}
        title={dialog.title}
        closeOnOverlayClick={false}
        closeOnEsc={false}
        onConfirm={handleConfirm}
        onCancel={handleCancel}
        onClose={handleCancel}
      >
        {dialog.message}
      </ModalConfirm>
    </div>
  );
}
