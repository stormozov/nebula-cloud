import { toast } from "react-toastify";

import { useToggleAdminMutation } from "@/entities/user";
import { Button, type ModalConfirmDialogRequest } from "@/shared/ui";

/**
 * Props interface for the ToggleAdminButton component.
 */
export interface ToggleAdminButtonProps {
  userId: number;
  isStaff: boolean;
  fullWidth?: boolean;
  disabled?: boolean;
  requestConfirm: ModalConfirmDialogRequest;
  onSuccess?: () => void;
}

/**
 * A button component that allows toggling a user's administrator (staff) role.
 *
 * @example
 * <ToggleAdminButton
 *   userId={123}
 *   isStaff={false}
 *   requestConfirm={requestConfirm}
 *   onSuccess={() => console.log("Admin status updated")}
 * />
 */
export function ToggleAdminButton({
  userId,
  isStaff,
  fullWidth = false,
  disabled = false,
  requestConfirm,
  onSuccess,
}: ToggleAdminButtonProps) {
  const [toggleAdmin, { isLoading }] = useToggleAdminMutation();

  const handleToggle = async () => {
    requestConfirm(
      "Изменение роли админа",
      "Вы действительно хотите изменить роль администратора?",
      async () => {
        try {
          await toggleAdmin({ id: userId, isStaff: !isStaff }).unwrap();
          onSuccess?.();
          toast.success(
            `Роль администратора пользователя ${userId} успешно изменена`,
            {
              position: "top-center",
            }
          );
        } catch {
          toast.error("Не удалось изменить роль администратора");
        }
      },
    );
  };

  return (
    <Button
      variant="danger"
      icon={{
        name: isStaff ? (disabled ? "lock" : "person") : "adminStatus",
      }}
      title={disabled ? "Вы не можете изменить роль администратора" : ""}
      fullWidth={fullWidth}
      loading={isLoading}
      disabled={disabled}
      onClick={handleToggle}
    >
      {isStaff ? "Снять роль администратора" : "Назначить роль администратора"}
    </Button>
  );
}
