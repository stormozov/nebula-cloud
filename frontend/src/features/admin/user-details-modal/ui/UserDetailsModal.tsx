import { AiOutlineClose } from "react-icons/ai";
import { FaUser } from "react-icons/fa6";

import { useGetStorageStatsQuery, useGetUserQuery } from "@/entities/user";
import { Button, Heading, PageWrapper } from "@/shared/ui";

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
  const { data: user, isLoading } = useGetUserQuery(userId, { skip: !userId });
  const { data: storageStats } = useGetStorageStatsQuery(userId, {
    skip: !userId,
  });

  if (isLoading) return <div>Загрузка...</div>;
  if (!user) return <div>Пользователь не найден</div>;

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
              </Heading>
              <Button variant="secondary" onClick={onClose}>
                <AiOutlineClose />
              </Button>
            </PageWrapper>
          </header>

          <div className="user-details-modal__content">
            <PageWrapper className="user-details-modal__info-wrapper">
              <UserDetailsModalInfo user={user} storageStats={storageStats} />
            </PageWrapper>
          </div>
        </div>
      </aside>
    </div>
  );
}
