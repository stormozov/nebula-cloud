import { useNavigate } from "react-router";

import { Button } from "@/shared/ui";

import "./UserDiskButton.scss";

/**
 * Interface defining the props for the UserDiskButton component.
 */
export interface UserDiskButtonProps {
  userId: number;
  isCurrentUser: boolean;
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
export function UserDiskButton({ userId, isCurrentUser }: UserDiskButtonProps) {
  const navigate = useNavigate();

  const currentNavigatePath = isCurrentUser
    ? "/disk"
    : `/admin/user/${userId}/disk`;

  return (
    <Button
      variant="secondary"
      icon={{ name: "folder" }}
      className="user-disk-button"
      onClick={() => navigate(currentNavigatePath)}
      fullWidth
    >
      Перейти к диску
    </Button>
  );
}
