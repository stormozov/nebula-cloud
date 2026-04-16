import { useNavigate } from "react-router";

import { useAppSelector } from "@/app/store/hooks";
import { selectUser } from "@/entities/user";

/**
 * Props interface for the `useNavigateToUserDisk` hook.
 */
interface IUseNavigateToUserDiskProps {
  /** The ID of the user whose disk should be navigated to. */
  userId: number;
}

/**
 * Return type of the `useNavigateToUserDisk` hook.
 */
interface IUseNavigateToUserDiskReturns {
  /** Function that navigates to the user's disk. */
  navigateToDisk: () => void;
}

/**
 * Custom hook that returns a function to navigate to a user's disk.
 */
export const useNavigateToUserDisk = ({
  userId,
}: IUseNavigateToUserDiskProps): IUseNavigateToUserDiskReturns => {
  const navigate = useNavigate();

  const currentUser = useAppSelector(selectUser);

  const isCurrentUser = currentUser?.id === userId;

  const currentNavigatePath = isCurrentUser
    ? "/disk"
    : `/admin/user/${userId}/disk`;

  const navigateToDisk = () => navigate(currentNavigatePath);

  return { navigateToDisk };
};
