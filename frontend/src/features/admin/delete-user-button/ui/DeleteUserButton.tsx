import { toast } from "react-toastify";

import { useDeleteUserMutation } from "@/entities/user";
import { Button, type ModalConfirmDialogRequest } from "@/shared/ui";

/**
 * Props interface for the DeleteUserButton component.
 */
export interface IDeleteUserButtonProps {
  userId: number;
  fullWidth?: boolean;
  disabled?: boolean;
  requestConfirm: ModalConfirmDialogRequest;
  onSuccess?: (message: string) => void;
}

/**
 * A button component that allows deleting a user with confirmation via API.
 *
 * @example
 * <DeleteUserButton
 *   userId={123}
 *   disabled={!canDelete}
 *   requestConfirm={requestConfirm}
 *   onSuccess={(msg) => alert(msg)}
 * />
 */
export function DeleteUserButton({
  userId,
  fullWidth = false,
  disabled = false,
  requestConfirm,
  onSuccess,
}: IDeleteUserButtonProps) {
  const [deleteUser, { isLoading }] = useDeleteUserMutation();

  const handleDelete = async () => {
    requestConfirm(
      "Удаление пользователя",
      `Вы действительно хотите удалить пользователя (ID: ${userId})?`,
      async () => {
        try {
          const response = await deleteUser(userId).unwrap();
          onSuccess?.(response.detail);
          toast.success(`Пользователь (ID: ${userId}) успешно удален`);
        } catch {
          toast.error("Не удалось удалить пользователя");
        }
      },
    );
  };

  return (
    <Button
      variant="danger"
      icon={{ name: disabled ? "lock" : "deleteUser" }}
      fullWidth={fullWidth}
      loading={isLoading}
      disabled={disabled}
      onClick={handleDelete}
    >
      Удалить
    </Button>
  );
}
