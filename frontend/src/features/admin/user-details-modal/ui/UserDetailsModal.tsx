import { useState } from "react";
import { AiOutlineClose } from "react-icons/ai";
import { FaUser } from "react-icons/fa6";

import { useAppSelector } from "@/app/store/hooks";
import {
  selectUser,
  useGetStorageStatsQuery,
  useGetUserQuery,
} from "@/entities/user";
import { Button, Heading, PageWrapper } from "@/shared/ui";

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
  onClose: () => void;
}

/**
 * Modal component that displays detailed information about a user.
 *
 * Fetches user data and storage statistics using RTK Query hooks.
 *
 * @example
 * <UserDetailsModal userId="123" onClose={() => setShowModal(false)} />
 */
export function UserDetailsModal({ userId, onClose }: IUserDetailsModalProps) {
  const [action, setAction] = useState<UserDetailsModalActionsType>("none");

  const currentUser = useAppSelector(selectUser);

  const { data: user, isLoading } = useGetUserQuery(userId, { skip: !userId });
  const { data: storageStats } = useGetStorageStatsQuery(userId, {
    skip: !userId,
  });

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
    onClose();
    console.log("Success delete user", message);
  };

  if (isLoading) return <div>Загрузка...</div>;
  if (!user) return <div>Пользователь не найден</div>;

  const isCurrentUser = currentUser?.id === user.id;

  const actionsProps: IUserDetailsModalActionsProps = {
    user,
    action,
    isCurrentUser,
    setAction,
    onClose: handleInlineFormClose,
    editFormSuccess: handleEditFormActionSuccess,
    resetPasswordFormSuccess: handleResetPasswordFormActionSuccess,
    toggleActiveSuccess: handleToggleActiveSuccess,
    toggleAdminSuccess: handleToggleAdminSuccess,
    deleteUserSuccess: handleDeleteUserSuccess,
  };

  return (
    <div className="user-details-modal">
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
                <FaUser className="user-details-modal__header-icon" />
                Детали пользователя {user?.username || user?.fullName}
                {isCurrentUser ? <span>Вы</span> : ""}
              </Heading>
              <Button variant="secondary" onClick={onClose}>
                <AiOutlineClose />
              </Button>
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
