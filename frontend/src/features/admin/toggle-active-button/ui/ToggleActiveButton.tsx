import { BsFillLightbulbFill, BsLightbulbOffFill } from "react-icons/bs";
import { FaLock } from "react-icons/fa";

import { useUpdateUserMutation } from "@/entities/user";
import { Button, type ModalConfirmDialogRequest } from "@/shared/ui";

/**
 * Props interface for the ToggleActiveButton component.
 */
interface ToggleActiveButtonProps {
  userId: number;
  isActive: boolean;
  fullWidth?: boolean;
  disabled?: boolean;
  requestConfirm: ModalConfirmDialogRequest;
  onSuccess?: () => void;
}

/**
 * A button component that allows toggling a user's active/inactive status.
 *
 * @example
 * <ToggleActiveButton
 *   userId={123}
 *   isActive={true}
 *   requestConfirm={requestConfirm}
 *   onSuccess={() => console.log("Status updated")}
 * />
 */

export function ToggleActiveButton({
  userId,
  isActive,
  fullWidth = false,
  disabled = false,
  requestConfirm,
  onSuccess,
}: ToggleActiveButtonProps) {
  const [updateUser, { isLoading }] = useUpdateUserMutation();

  const handleToggle = async () => {
    requestConfirm(
      "Изменение статуса учетной записи",
      "Вы действительно хотите изменить активность пользователя?",
      async () => {
        try {
          await updateUser({
            id: userId,
            data: { is_active: !isActive },
          }).unwrap();
          onSuccess?.();
        } catch (err) {
          console.error("Failed to toggle active status:", err);
        }
      },
    );
  };

  return (
    <Button
      variant={isActive ? "danger" : "primary"}
      title={disabled ? "Вы не можете деактивировать пользователя" : ""}
      fullWidth={fullWidth}
      loading={isLoading}
      disabled={disabled}
      onClick={handleToggle}
    >
      {isActive ? (
        <>
          {disabled ? <FaLock /> : <BsLightbulbOffFill />}
          Деактивировать
        </>
      ) : (
        <>
          {disabled ? <FaLock /> : <BsFillLightbulbFill />}
          Активировать
        </>
      )}
    </Button>
  );
}
