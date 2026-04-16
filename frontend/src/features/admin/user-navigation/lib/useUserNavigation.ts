import { useCallback, useMemo } from "react";

import type { SelectUser } from "@/widgets/admin-user-manager";

/**
 * Interface defining the props for the `useUserNavigation` hook.
 */
export interface IUseUserNavigationProps {
  currentUserId: SelectUser;
  allUserIds: number[];
  hasPaginationMore: boolean;
  onNavigate: (userId: number) => void;
  onLoadMore: (shouldAutoNavigate: boolean) => void;
}

/**
 * Custom React Hook that manages navigation logic between a list of users.
 */
export const useUserNavigation = ({
  currentUserId,
  allUserIds,
  onNavigate,
  hasPaginationMore,
  onLoadMore,
}: IUseUserNavigationProps) => {
  const currentIndex = useMemo(() => {
    return allUserIds.indexOf(currentUserId ?? 0);
  }, [currentUserId, allUserIds]);
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < allUserIds.length - 1 || hasPaginationMore;

  const handlePrev = useCallback(() => {
    if (hasPrev) onNavigate(allUserIds[currentIndex - 1]);
  }, [hasPrev, onNavigate, allUserIds, currentIndex]);

  const handleNext = useCallback(() => {
    if (currentIndex < allUserIds.length - 1) {
      onNavigate(allUserIds[currentIndex + 1]);
    } else if (hasPaginationMore && onLoadMore) {
      onLoadMore(true);
      // Widget will auto-navigate to first new user post-load
    }
  }, [currentIndex, allUserIds, hasPaginationMore, onLoadMore, onNavigate]);

  return {
    hasPrev,
    hasNext,
    handlePrev,
    handleNext,
  };
};
