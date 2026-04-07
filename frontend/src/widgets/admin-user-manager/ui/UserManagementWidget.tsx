import {
  type IUserDetailsModalProps,
  UserDetailsModal,
  UserList,
  UserSearchInput,
} from "@/features/admin";
import { Button, ModalConfirm } from "@/shared/ui";

import { useUserManager } from "../lib/useUserManager";

import "./UserManagementWidget.scss";

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
        <div className="users-management__count">
          Всего пользователей: {usersList.totalCount}
        </div>
      </header>

      <UserList
        users={usersList.items}
        states={usersList.states}
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

      {selected.userId && (
        <UserDetailsModal
          modalProps={userDetailsModal as IUserDetailsModalProps["modalProps"]}
        />
      )}

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
