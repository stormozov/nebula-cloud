import classNames from "classnames";
import { useRef } from "react";
import { createPortal } from "react-dom";

import { type IModalContentProps, UserNavigation } from "@/features/admin";
import { useBodyScrollLock, useFocusTrap } from "@/shared/hooks";
import {
  Badge,
  Button,
  Heading,
  Icon,
  PageWrapper,
  Spinner,
} from "@/shared/ui";

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
  useBodyScrollLock(true);

  const modalContentRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useFocusTrap({
    active: !isClosing,
    containerRef: modalContentRef,
    onEscape: handleCloseWithAnimation,
    initialFocusRef: closeButtonRef,
  });

  const hasError = !isLoading && !user;
  const isSuccess = !isLoading && user && actionsProps;

  const renderLoadingState = () => (
    <div className="user-details-modal__loading-state">
      <Spinner
        size="xlarge"
        color="tertiary"
        text="Загрузка информации о пользователе..."
      />
    </div>
  );

  const renderErrorState = () => (
    <div className="user-details-modal__error-state">
      <Icon name="cloudBad" size={124} />
      <Heading level={3}>Не удалось загрузить данные</Heading>
      <p className="user-details-modal__error-text">
        Пользователь не найден или произошла ошибка
      </p>
      <Button
        variant="primary"
        icon={{ name: "close" }}
        onClick={handleCloseWithAnimation}
      >
        Закрыть
      </Button>
    </div>
  );

  const renderContent = () => {
    if (!isSuccess) return null;
    return (
      <>
        <UserDetailsModalInfo user={user} storageStats={storageStats} />
        <UserDetailsModalActions actionProps={actionsProps} />
      </>
    );
  };

  const renderMainContent = () => {
    if (isLoading) return renderLoadingState();
    if (hasError) return renderErrorState();
    return renderContent();
  };

  const modalContent = (
    <div className={classNames("user-details-modal", { closing: isClosing })}>
      <div className="user-details-modal__overlay" />
      <aside
        ref={modalContentRef}
        className="user-details-modal__content-wrapper"
      >
        <div className="container">
          <header className="user-details-modal__header">
            <PageWrapper
              className="user-details-modal__header-wrapper"
              align="center"
              justify="space-between"
            >
              <Heading level={3} className="user-details-modal__header-title">
                <Icon name="person" color="primary" />

                {isLoading && "Загрузка данных..."}
                {hasError && "Пользователь не найден"}
                {isSuccess &&
                  `Детали пользователя ${user.username || user.fullName}`}

                {isSuccess && isCurrentUser && (
                  <Badge variant="info-light" superscript>
                    Вы
                  </Badge>
                )}
              </Heading>
              <PageWrapper>
                {isSuccess && (
                  <UserNavigation
                    currentUserId={navigationProps.currentUserId}
                    allUserIds={navigationProps.allUserIds}
                    hasPaginationMore={navigationProps.hasPaginationMore}
                    onLoadMore={navigationProps.onLoadMore}
                    onNavigate={navigationProps.onNavigate}
                  />
                )}
                <Button
                  ref={closeButtonRef}
                  variant="secondary"
                  size="small"
                  icon={{ name: "close" }}
                  title="Закрыть окно (ESC)"
                  aria-label="Закрыть окно"
                  onClick={handleCloseWithAnimation}
                />
              </PageWrapper>
            </PageWrapper>
          </header>

          <PageWrapper className="user-details-modal__content">
            {renderMainContent()}
          </PageWrapper>
        </div>
      </aside>
    </div>
  );

  return typeof document !== "undefined"
    ? createPortal(modalContent, document.body)
    : null;
}
