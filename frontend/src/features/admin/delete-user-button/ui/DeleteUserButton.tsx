import { FaLock, FaUserTimes } from "react-icons/fa";

import { useDeleteUserMutation } from "@/entities/user";
import { Button } from "@/shared/ui";

/**
 * Props interface for the DeleteUserButton component.
 */
export interface IDeleteUserButtonProps {
  userId: number;
  fullWidth?: boolean;
  disabled?: boolean;
  onSuccess?: (message: string) => void;
}

/**
 * A button component that allows deleting a user with confirmation via API.
 *
 * @example
 * <DeleteUserButton
 *   userId={123}
 *   onSuccess={(msg) => alert(msg)}
 *   disabled={!canDelete}
 * />
 */
export function DeleteUserButton({
  userId,
  onSuccess,
  fullWidth = false,
  disabled = false,
}: IDeleteUserButtonProps) {
  const [deleteUser, { isLoading }] = useDeleteUserMutation();

  const handleDelete = async () => {
    try {
      const response = await deleteUser(userId).unwrap();
      onSuccess?.(response.detail);
    } catch (err) {
      console.error("Failed to delete user:", err);
    }
  };

  return (
    <Button
      variant="danger"
      fullWidth={fullWidth}
      loading={isLoading}
      disabled={disabled}
      onClick={handleDelete}
    >
      {disabled ? <FaLock /> : <FaUserTimes />}
      Удалить
    </Button>
  );
}
