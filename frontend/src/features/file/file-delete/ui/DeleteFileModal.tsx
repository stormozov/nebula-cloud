import type { IFile } from "@/entities/file";
import { Button, Icon, Modal } from "@/shared/ui";

import "./DeleteFileModal.scss";

/**
 * Props for DeleteFileModal component.
 */
export interface IDeleteFileModalProps {
  /** Whether modal is visible. */
  isOpen: boolean;
  /** File to delete. */
  file: IFile | null;
  /** Callback when modal should be closed. */
  onClose: () => void;
  /** Callback when delete is confirmed. */
  onConfirm: () => void | Promise<void>;
  /** Whether delete is in progress. */
  isDeleting?: boolean;
}

/**
 * Modal for confirming file deletion.
 *
 * Shows file name and warning about irreversible action.
 */
export function DeleteFileModal({
  isOpen,
  file,
  onClose,
  onConfirm,
  isDeleting = false,
}: IDeleteFileModalProps) {
  const handleConfirm = async (): Promise<void> => {
    await onConfirm();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Удаление файла"
      ariaLabel="Подтверждение удаления файла"
      closeOnOverlayClick={!isDeleting}
      closeOnEsc={!isDeleting}
      footer={
        <>
          <Button
            variant="secondary"
            icon={{ name: "close" }}
            disabled={isDeleting}
            onClick={onClose}
          >
            Отмена
          </Button>
          <Button
            variant="danger"
            icon={{ name: "trash" }}
            onClick={handleConfirm}
            loading={isDeleting}
          >
            Удалить
          </Button>
        </>
      }
    >
      <div className="delete-file-modal">
        <div className="delete-file-modal__icon">
          <Icon name="warning" size="60" color="warning" />
        </div>
        <div className="delete-file-modal__message">
          <p>
            Вы уверены, что хотите удалить файл{" "}
            <strong color="var(--color-error)">"{file?.originalName}"</strong>?
          </p>
          <p className="delete-file-modal__warning">
            Это действие нельзя отменить.
          </p>
        </div>
      </div>
    </Modal>
  );
}
