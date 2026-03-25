import { useState } from "react";

import { UserDetailsModal, UserList } from "@/features/admin";
import { ModalConfirm, useModalConfirm } from "@/shared/ui";

export function UserManagementWidget() {
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);

  const { dialog, requestConfirm, handleConfirm, handleCancel } =
    useModalConfirm();

  return (
    <>
      <UserList onSelectUser={setSelectedUserId} />

      {selectedUserId && (
        <UserDetailsModal
          userId={selectedUserId}
          requestConfirm={requestConfirm}
          onClose={() => setSelectedUserId(null)}
        />
      )}

      <ModalConfirm
        isOpen={dialog.isOpen}
        title={dialog.title}
        onConfirm={handleConfirm}
        onCancel={handleCancel}
        onClose={handleCancel}
      >
        {dialog.message}
      </ModalConfirm>
    </>
  );
}
