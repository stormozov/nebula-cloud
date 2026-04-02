import classNames from "classnames";

import { type IModalContentProps, UserNavigation } from "@/features/admin";
import { Button, Heading, Icon, PageWrapper } from "@/shared/ui";

import { useUserDetailsModal } from "../../lib/useUserDetailsModal";
import { UserDetailsModalActions } from "../UserDetailsModalActions/UserDetailsModalActions";
import { UserDetailsModalInfo } from "../UserDetailsModalInfo/UserDetailsModalInfo";

import "./UserDetailsModal.scss";

/**
 * Props interface for the `UserDetailsModal` component.
 */
export interface IUserDetailsModalProps {
  modalProps: IModalContentProps;
}

/**
 * Modal component that displays detailed information about a user.
 */
export function UserDetailsModal({ modalProps }: IUserDetailsModalProps) {
  const {
    user,
    storageStats,
    isLoading,
    isClosing,
    actionsProps,
    isCurrentUser,
    navigationProps,
    handleCloseWithAnimation,
  } = useUserDetailsModal(modalProps);

  if (isLoading) return <div>Загрузка...</div>;
  if (!user || !actionsProps.user) return <div>Пользователь не найден</div>;

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
                  currentUserId={navigationProps.currentUserId}
                  allUserIds={navigationProps.allUserIds}
                  hasPaginationMore={navigationProps.hasPaginationMore}
                  onLoadMore={navigationProps.onLoadMore}
                  onNavigate={navigationProps.onNavigate}
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
