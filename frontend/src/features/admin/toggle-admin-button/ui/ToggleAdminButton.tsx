import { BsFillPersonFill } from "react-icons/bs";
import { FaLock } from "react-icons/fa";
import { RiAdminFill } from "react-icons/ri";

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
          await toggleAdmin({ id: userId, is_staff: !isStaff }).unwrap();
          onSuccess?.();
        } catch (err) {
          console.error("Failed to toggle admin status:", err);
        }
      },
    );
  };

  return (
    <Button
      variant="danger"
      title={disabled ? "Вы не можете изменить роль администратора" : ""}
      fullWidth={fullWidth}
      loading={isLoading}
      disabled={disabled}
      onClick={handleToggle}
    >
      {isStaff ? (
        <>
          {disabled ? <FaLock /> : <BsFillPersonFill />}
          Снять роль администратора
        </>
      ) : (
        <>
          {disabled ? <FaLock /> : <RiAdminFill />}
          Назначить роль администратора
        </>
      )}
    </Button>
  );
}
