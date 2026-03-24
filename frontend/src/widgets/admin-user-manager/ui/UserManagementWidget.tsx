import { useState } from "react";

import { UserDetailsModal, UserList } from "@/features/admin";

export function UserManagementWidget() {
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);

  return (
    <>
      <UserList onSelectUser={setSelectedUserId} />
      {selectedUserId && (
        <UserDetailsModal
          userId={selectedUserId}
          onClose={() => setSelectedUserId(null)}
        />
      )}
    </>
  );
}
