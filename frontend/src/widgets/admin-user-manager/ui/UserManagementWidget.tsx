import { UserDetailsModal, UserList, UserSearchInput } from "@/features/admin";
import { Badge, Button, Heading, ModalConfirm } from "@/shared/ui";

import { useUserManager } from "../lib/useUserManager";

import "./UserManagementWidget.scss";

/**
 * A widget component for managing users in the admin dashboard.
 */
export function UserManagementWidget() {
  const {
    usersList,
    selected,
    pagination,
    search,
    confirmModal,
    userDetailsModal,
  } = useUserManager();

  return (
    <div className="users-management w-full">
      <header className="users-management__header">
        <Heading level={2} noMargin className="users-management__header-title">
          Управление пользователями
        </Heading>

        <div className="users-management__count">
          <Badge icon="person" superscript>
            {usersList.totalCount} пользователей
          </Badge>
        </div>

        <UserSearchInput
          buttonProps={{
            children: "Поиск",
            size: "small",
          }}
          inputProps={{
            value: search.term,
            className: "users-management__search",
            placeholder: "Поиск по ID, логину или email",
            onChange: search.setTerm,
          }}
        />
      </header>

      <UserList
        users={usersList.items}
        states={usersList.states}
        renders={usersList.renders}
        onSelectUser={selected.setUserId}
      />

      {usersList.items.length > 0 && usersList.hasMore && (
        <div className="users-management__load-more">
          <Button
            icon={{ name: "retry" }}
            loading={pagination.isLoadMoreLoading}
            disabled={pagination.isLoadMoreLoading}
            onClick={() => pagination.loadMore(false)}
          >
            Загрузить еще
          </Button>
        </div>
      )}

      {selected.userId && <UserDetailsModal modalProps={userDetailsModal} />}

      <ModalConfirm
        isOpen={confirmModal.isOpen}
        title={confirmModal.title}
        closeOnOverlayClick={false}
        closeOnEsc={false}
        onConfirm={confirmModal.handleConfirm}
        onCancel={confirmModal.handleCancel}
        onClose={confirmModal.handleCancel}
      >
        {confirmModal.message}
      </ModalConfirm>
    </div>
  );
}
