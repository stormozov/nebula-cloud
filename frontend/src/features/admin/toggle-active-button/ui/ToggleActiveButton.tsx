import { BsFillLightbulbFill, BsLightbulbOffFill } from "react-icons/bs";

import { useUpdateUserMutation } from "@/entities/user";
import { Button } from "@/shared/ui";

/**
 * Props interface for the ToggleActiveButton component.
 */
interface ToggleActiveButtonProps {
  userId: number;
  isActive: boolean;
  fullWidth?: boolean;
  disabled?: boolean;
  onSuccess?: () => void;
}

/**
 * A button component that allows toggling a user's active/inactive status.
 *
 * @example
 * <ToggleActiveButton
 *   userId={123}
 *   isActive={true}
 *   onSuccess={() => console.log("Status updated")}
 * />
 */

export function ToggleActiveButton({
  userId, isActive, fullWidth = false, disabled = false, onSuccess,
}: ToggleActiveButtonProps) {
  const [updateUser] = useUpdateUserMutation();

  const handleToggle = async () => {
    try {
      await updateUser({ id: userId, data: { is_active: !isActive } }).unwrap();
      onSuccess?.();
    } catch (err) {
      console.error("Failed to toggle active status:", err);
    }
  };

  return (
    <Button
      variant={isActive ? "danger" : "primary"}
      title={disabled ? "Вы не можете деактивировать пользователя" : ""}
      fullWidth={fullWidth}
      disabled={disabled}
      onClick={handleToggle}
    >
      {isActive ? (
        <>
          <BsLightbulbOffFill />
          Деактивировать
        </>
      ) : (
        <>
          <BsFillLightbulbFill />
          Активировать
        </>
      )}
    </Button>
  );
}
