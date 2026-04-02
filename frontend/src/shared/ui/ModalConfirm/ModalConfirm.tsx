import { useState } from "react";

import { Button } from "../buttons";
import { Icon } from "../Icon";
import { PageWrapper } from "../layouts";
import { Modal } from "../Modal";

import "./ModalConfirm.scss";

/**
 * Props interface for the ModalConfirm component.
 */
export interface ModalConfirmProps {
  isOpen: boolean;
  title?: string;
  closeOnOverlayClick?: boolean;
  closeOnEsc?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void | Promise<void>;
  onClose: () => void;
  children?: React.ReactNode;
}

/**
 * A reusable confirmation modal component with loading state management.
 *
 * Displays a dialog that prompts the user to confirm or cancel an action.
 * Prevents interaction while async operations are in progress. Supports
 * customization of behavior via props like close-on-click or esc.
 *
 * @example
 * <ModalConfirm
 *   isOpen={isConfirmOpen}
 *   title="Delete item"
 *   onConfirm={handleDelete}
 *   onCancel={() => {}}
 *   onClose={() => setIsConfirmOpen(false)}
 * >
 *   Are you sure you want to delete this item?
 * </ModalConfirm>
 */
export function ModalConfirm({
  isOpen,
  title = "Подтвердите действие",
  closeOnOverlayClick = true,
  closeOnEsc = true,
  onConfirm,
  onCancel,
  onClose,
  children,
}: ModalConfirmProps) {
  const [isLoading, setIsLoading] = useState(false);

  const handleConfirm = async () => {
    if (isLoading) return;
    setIsLoading(true);
    try {
      await onConfirm();
      onClose();
    } catch (error) {
      console.error("Confirm action failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCancel = async () => {
    if (isLoading) return;
    setIsLoading(true);
    try {
      await onCancel();
      onClose();
    } catch (error) {
      console.error("Cancel action failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const modalProps = {
    isOpen,
    title,
    closeOnOverlayClick: closeOnOverlayClick && !isLoading,
    closeOnEsc: closeOnEsc && !isLoading,
    onClose: handleCancel,
  };

  return (
    <Modal className="modal-confirm" {...modalProps}>
      {children && <div className="modal-confirm__content">{children}</div>}
      <PageWrapper className="modal-confirm__actions" justify="center">
        <Button variant="secondary" onClick={handleCancel} disabled={isLoading}>
          <Icon name="close" />
          Отменить
        </Button>
        <Button variant="primary" onClick={handleConfirm} disabled={isLoading}>
          {isLoading ? (
            "Загрузка..."
          ) : (
            <>
              <Icon name="check" />
              Подтвердить
            </>
          )}
        </Button>
      </PageWrapper>
    </Modal>
  );
}
