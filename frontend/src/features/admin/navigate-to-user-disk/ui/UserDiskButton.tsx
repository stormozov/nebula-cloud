import { useNavigateToUserDisk } from "@/shared/hooks";
import { Button } from "@/shared/ui";

import "./UserDiskButton.scss";

/**
 * Interface defining the props for the UserDiskButton component.
 */
export interface IUserDiskButtonProps {
  /** The ID of the user whose disk should be navigated to. */
  userId: number;
}

/**
 * A button component that navigates to a user's file disk.
 *
 * The navigation path depends on whether the user is viewing their own disk
 * or another user's disk. If `isCurrentUser` is true, it navigates to `/disk`;
 * otherwise, it uses the admin route `/admin/user/{userId}/disk`.
 *
 * @example
 * ```tsx
 * <UserDiskButton userId={123} isCurrentUser={false} />
 * ```
 */
export function UserDiskButton({ userId }: IUserDiskButtonProps) {
  const { navigateToDisk } = useNavigateToUserDisk({ userId });

  return (
    <Button
      variant="secondary"
      icon={{ name: "folder" }}
      className="user-disk-button"
      fullWidth
      onClick={() => navigateToDisk()}
    >
      Перейти к диску
    </Button>
  );
}
