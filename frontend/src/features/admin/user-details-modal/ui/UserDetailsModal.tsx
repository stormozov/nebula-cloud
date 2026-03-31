import classNames from "classnames";
import { useCallback, useEffect, useState } from "react";

import { useAppSelector } from "@/app/store/hooks";
import {
  selectUser,
  useGetStorageStatsQuery,
  useGetUserQuery,
} from "@/entities/user";
import { UserNavigation } from "@/features/admin";
import {
  Button,
  Heading,
  Icon,
  type ModalConfirmDialogRequest,
  PageWrapper,
} from "@/shared/ui";

import type {
  IUserDetailsModalActionsProps,
  UserDetailsModalActionsType,
} from "../lib/types";
import { UserDetailsModalActions } from "./UserDetailsModalActions";
import { UserDetailsModalInfo } from "./UserDetailsModalInfo";

import "./UserDetailsModal.scss";

/**
 * Props interface for the UserDetailsModal component.
 */
interface IUserDetailsModalProps {
  userId: number;
  allUserIds: number[];
  hasPaginationMore: boolean;
  onLoadMore: () => void;
  onNavigate: (userId: number) => void;
  requestConfirm: ModalConfirmDialogRequest;
  onClose: () => void;
  isConfirmOpen?: boolean;
}

/**
 * Modal component that displays detailed information about a user.
 *
 * Fetches user data and storage statistics using RTK Query hooks.
 *
 * @example
 * <UserDetailsModal userId="123" onClose={() => setShowModal(false)} />
 */
export function UserDetailsModal({
  userId,
  allUserIds,
  hasPaginationMore,
  onLoadMore,
  onNavigate,
  requestConfirm,
  onClose,
  isConfirmOpen = false,
}: IUserDetailsModalProps) {
  const [action, setAction] = useState<UserDetailsModalActionsType>("none");
  const [isClosing, setIsClosing] = useState(false);

  const currentUser = useAppSelector(selectUser);

  const { data: user, isLoading } = useGetUserQuery(userId, { skip: !userId });
  const { data: storageStats } = useGetStorageStatsQuery(userId, {
    skip: !userId,
  });

  const handleCloseWithAnimation = useCallback(() => {
    if (isClosing) return;
    setIsClosing(true);
    setTimeout(() => onClose(), 300);
  }, [isClosing, onClose]);

  const handleInlineFormClose = () => setAction("none");

  const handleEditFormActionSuccess = () => {
    setAction("none");
    console.log("Success edit form");
  };

  const handleResetPasswordFormActionSuccess = (message: string) => {
    setAction("none");
    console.log(message);
  };

  const handleToggleActiveSuccess = () => {
    setAction("none");
    console.log("Success toggle active");
  };

  const handleToggleAdminSuccess = () => {
    setAction("none");
    console.log("Success toggle admin");
  };

  const handleDeleteUserSuccess = (message: string) => {
    handleCloseWithAnimation();
    console.log("Success delete user", message);
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !isConfirmOpen) {
        e.preventDefault();
        handleCloseWithAnimation();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleCloseWithAnimation, isConfirmOpen]);

  if (isLoading) return <div>Загрузка...</div>;
  if (!user) return <div>Пользователь не найден</div>;

  const isCurrentUser = currentUser?.id === user.id;

  const actionsProps: IUserDetailsModalActionsProps = {
    user,
    action,
    isCurrentUser,
    setAction,
    requestConfirm,
    onClose: handleInlineFormClose,
    editFormSuccess: handleEditFormActionSuccess,
    resetPasswordFormSuccess: handleResetPasswordFormActionSuccess,
    toggleActiveSuccess: handleToggleActiveSuccess,
    toggleAdminSuccess: handleToggleAdminSuccess,
    deleteUserSuccess: handleDeleteUserSuccess,
  };

  return (
    <div className={classNames("user-details-modal", { closing: isClosing })}>
      <div className="user-details-modal__overlay" />
      <aside className="user-details-modal__content-wrapper">
        <div className="container">
          <header className="user-details-modal__header">
            <PageWrapper
              className="user-details-modal__header-wrapper"
              align="center"
              justify="space-between"
            >
              <Heading level={3} className="user-details-modal__header-title">
                <Icon name="person" color="primary" />
                Детали пользователя {user?.username || user?.fullName}
                {isCurrentUser ? (
                  <sup
                    title="Текущий пользователь"
                    className="user-details-modal__header-title-badge"
                  >
                    Вы
                  </sup>
                ) : (
                  ""
                )}
              </Heading>
              <PageWrapper>
                <UserNavigation
                  currentUserId={user.id}
                  allUserIds={allUserIds}
                  hasPaginationMore={hasPaginationMore}
                  onLoadMore={onLoadMore}
                  onNavigate={onNavigate}
                />
                <Button
                  variant="secondary"
                  size="small"
                  title="Закрыть окно (ESC)"
                  aria-label="Закрыть окно"
                  onClick={handleCloseWithAnimation}
                >
                  <Icon name="close" />
                </Button>
              </PageWrapper>
            </PageWrapper>
          </header>

          <PageWrapper className="user-details-modal__content">
            <UserDetailsModalInfo user={user} storageStats={storageStats} />
            <UserDetailsModalActions actionProps={actionsProps} />
          </PageWrapper>
        </div>
      </aside>
    </div>
  );
}
