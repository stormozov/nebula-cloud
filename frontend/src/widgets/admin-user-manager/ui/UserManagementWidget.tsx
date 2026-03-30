import { useState } from "react";

import { useGetUsersQuery } from "@/entities/user";
import { UserDetailsModal, UserList } from "@/features/admin";
import { ModalConfirm, useModalConfirm } from "@/shared/ui";

export function UserManagementWidget() {
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);

  const {
    data: users,
    isLoading: usersLoading,
    error: usersError,
  } = useGetUsersQuery();

  const { dialog, requestConfirm, handleConfirm, handleCancel } =
    useModalConfirm();

  const allUserIds = users?.results.map((user) => user.id) ?? [];

  return (
    <>
      <UserList
        users={users?.results ?? []}
        isLoading={usersLoading}
        error={usersError}
        onSelectUser={setSelectedUserId}
      />

      {selectedUserId && (
        <UserDetailsModal
          userId={selectedUserId}
          allUserIds={allUserIds}
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
    </>
  );
}
