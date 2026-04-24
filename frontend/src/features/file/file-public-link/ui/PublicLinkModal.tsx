import { useEffect, useState } from "react";

import type { IFile } from "@/entities/file";
import { Button, ControlledInput, Icon } from "@/shared/ui";
import { Modal } from "@/shared/ui/Modal";

import "./PublicLinkModal.scss";

/**
 * Props for PublicLinkModal component.
 */
export interface IPublicLinkModalProps {
  /** Whether modal is visible. */
  isOpen: boolean;
  /** File to manage public link for. */
  file: IFile | null;
  /** Callback when modal should be closed. */
  onClose: () => void;
  /** Callback when generate link is requested. */
  onGenerate: () => void | Promise<void>;
  /** Callback when copy link is requested. */
  onCopy: (url: string) => void | Promise<void>;
  /** Callback when delete link is requested. */
  onDelete: () => void | Promise<void>;
  /** Whether generate operation is in progress. */
  isGenerating?: boolean;
  /** Whether delete operation is in progress. */
  isDeleting?: boolean;
  /** Error message. */
  error?: string | null;
}

/**
 * Modal for managing file public link.
 *
 * Shows current link with copy button, or generate/delete buttons.
 */
export function PublicLinkModal({
  isOpen,
  file,
  onClose,
  onGenerate,
  onCopy,
  onDelete,
  isGenerating = false,
  isDeleting = false,
  error,
}: IPublicLinkModalProps) {
  const [copySuccess, setCopySuccess] = useState(false);

  const hasLink = file?.hasPublicLink && file?.publicLinkUrl;

  /**
   * Reset state when modal opens/closes.
   */
  useEffect(() => {
    if (isOpen) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setCopySuccess(false);
  }, [isOpen]);

  const handleCopyBtnClick = async (): Promise<void> => {
    if (!file?.publicLinkUrl) return;
    await onCopy(file.publicLinkUrl);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  const handleGenerateBtnClick = async (): Promise<void> => {
    await onGenerate();
  };

  const handleDeleteBtnClick = async (): Promise<void> => {
    await onDelete();
  };

  const handleClose = (): void => {
    if (!isGenerating && !isDeleting) onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Публичная ссылка"
      ariaLabel="Управление публичной ссылкой"
      closeOnOverlayClick={!isGenerating && !isDeleting}
      closeOnEsc={!isGenerating && !isDeleting}
      footer={
        <>
          <Button
            variant="secondary"
            icon={{ name: "close" }}
            disabled={isGenerating || isDeleting}
            onClick={handleClose}
          >
            Закрыть
          </Button>
          {hasLink && (
            <Button
              variant="danger"
              icon={{ name: "deleteLink" }}
              loading={isDeleting}
              onClick={handleDeleteBtnClick}
            >
              Удалить ссылку
            </Button>
          )}
        </>
      }
    >
      <div className="public-link-modal">
        {hasLink ? (
          <>
            <div className="public-link-modal__success">
              <Icon name="check" />
              <p>Публичная ссылка активна</p>
            </div>

            <ControlledInput
              type="text"
              value={file?.publicLinkUrl || ""}
              onChange={() => {}} // Read-only
              label="Ссылка для скачивания"
              disabled
              readOnly
            />

            <div className="public-link-modal__actions">
              <Button
                variant="primary"
                icon={{ name: copySuccess ? "check" : "copy" }}
                fullWidth
                disabled={isGenerating || isDeleting || copySuccess}
                onClick={handleCopyBtnClick}
              >
                {copySuccess ? "Скопировано!" : "Скопировать"}
              </Button>
            </div>

            <p className="public-link-modal__hint">
              Любой пользователь с этой ссылкой сможет скачать файл.
            </p>
          </>
        ) : (
          <>
            <div className="public-link-modal__info">
              <Icon name="infoSquare" size={20} />
              <p>Публичная ссылка ещё не создана</p>
            </div>

            <div className="public-link-modal__actions">
              <Button
                variant="primary"
                icon={{ name: "share" }}
                loading={isGenerating}
                fullWidth
                onClick={handleGenerateBtnClick}
              >
                Создать публичную ссылку
              </Button>
            </div>

            <p className="public-link-modal__hint">
              После создания вы сможете скопировать ссылку и поделиться ею с
              другими пользователями.
            </p>
          </>
        )}

        {error && (
          <div className="public-link-modal__error" role="alert">
            {error}
          </div>
        )}
      </div>
    </Modal>
  );
}
