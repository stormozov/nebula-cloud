import { toast } from "react-toastify";

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
            data: { isActive: !isActive },
          }).unwrap();
          onSuccess?.();
          toast.success(`Статус пользователя ${userId} успешно изменен`, {
            position: "top-center",
          });
        } catch {
          toast.error("Не удалось изменить статус пользователя");
        }
      },
    );
  };

  return (
    <Button
      variant={isActive ? "danger" : "primary"}
      icon={{
        name: isActive ? (disabled ? "lock" : "lightbulbOff") : "lightbulbOn",
      }}
      title={disabled ? "Вы не можете деактивировать пользователя" : ""}
      fullWidth={fullWidth}
      loading={isLoading}
      disabled={disabled}
      onClick={handleToggle}
    >
      {isActive ? "Деактивировать" : "Активировать"}
    </Button>
  );
}
