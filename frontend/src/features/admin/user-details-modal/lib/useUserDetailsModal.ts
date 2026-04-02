import { useCallback, useState } from "react";

import { useAppSelector } from "@/app/store/hooks";
import {
  selectUser,
  useGetStorageStatsQuery,
  useGetUserQuery,
} from "@/entities/user";

import type { IModalContentProps, UserDetailsModalActionsType } from "./types";
import { useModalClose } from "./useModalClose";

/**
 * Props for the `useUserDetailsModal` hook.
 */
type UseUserDetailsModalProps = IModalContentProps;

/**
 * Hook that provides data and actions for the `UserDetailsModal` component.
 */
export function useUserDetailsModal({
  userId,
  allUserIds,
  hasPaginationMore,
  onLoadMore,
  onNavigate,
  requestConfirm,
  onClose,
  isConfirmOpen = false,
}: UseUserDetailsModalProps) {
  const [action, setAction] = useState<UserDetailsModalActionsType>("none");

  const currentUser = useAppSelector(selectUser);
  const { data: user, isLoading } = useGetUserQuery(userId, { skip: !userId });
  const { data: storageStats } = useGetStorageStatsQuery(userId, {
    skip: !userId,
  });

  const { isClosing, handleCloseWithAnimation } = useModalClose({
    onClose,
    isBlocked: isConfirmOpen,
  });

  const handleInlineFormClose = useCallback(() => setAction("none"), []);
  const handleActionSuccess = useCallback(
    (message?: string, close?: boolean) => {
      handleInlineFormClose();
      if (close) handleCloseWithAnimation();
      if (message) console.log(message);
    },
    [handleInlineFormClose, handleCloseWithAnimation],
  );

  if (!user) return {};

  // Creating props for child components
  const actionsProps = {
    user,
    action,
    isCurrentUser: currentUser?.id === user?.id,
    setAction,
    requestConfirm,
    onSuccess: handleActionSuccess,
    onClose: handleInlineFormClose,
  };

  return {
    user,
    storageStats,
    isLoading,
    isClosing,
    actionsProps,
    isCurrentUser: currentUser?.id === user?.id,
    navigationProps: {
      currentUserId: userId,
      allUserIds,
      hasPaginationMore,
      onLoadMore,
      onNavigate,
    },
    handleCloseWithAnimation,
  };
}
