import { useCallback, useMemo } from "react";

/**
 * Interface defining the props for the `useUserNavigation` hook.
 */
export interface IUserNavigationProps {
  currentUserId: number;
  allUserIds: number[];
  onNavigate: (userId: number) => void;
}

/**
 * Custom React Hook that manages navigation logic between a list of users.
 */
export const useUserNavigation = ({
  currentUserId,
  allUserIds,
  onNavigate,
}: IUserNavigationProps) => {
  const currentIndex = useMemo(() => {
    return allUserIds.indexOf(currentUserId);
  }, [currentUserId, allUserIds]);
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < allUserIds.length - 1;

  const handlePrev = useCallback(() => {
    if (hasPrev) onNavigate(allUserIds[currentIndex - 1]);
  }, [hasPrev, onNavigate, allUserIds, currentIndex]);

  const handleNext = useCallback(() => {
    if (hasNext) onNavigate(allUserIds[currentIndex + 1]);
  }, [hasNext, onNavigate, allUserIds, currentIndex]);

  return {
    hasPrev,
    hasNext,
    handlePrev,
    handleNext,
  };
};
