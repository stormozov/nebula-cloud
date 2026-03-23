import { useEffect, useRef, useState } from "react";
import { AiOutlineClose } from "react-icons/ai";
import { FaSave } from "react-icons/fa";

import type { IFile } from "@/entities/file";
import { Button, ControlledTextarea } from "@/shared/ui";
import { Modal } from "@/shared/ui/Modal";

import "./EditCommentModal.scss";

/**
 * Props for EditCommentModal component.
 */
export interface IEditCommentModalProps {
  /** Whether modal is visible. */
  isOpen: boolean;
  /** File to edit comment for. */
  file: IFile | null;
  /** Callback when modal should be closed. */
  onClose: () => void;
  /** Callback when comment is submitted. */
  onSubmit: (newComment: string) => void | Promise<void>;
  /** Whether submission is in progress. */
  isSubmitting?: boolean;
  /** Error message. */
  error?: string | null;
}

/**
 * Modal for editing a file comment.
 *
 * Shows textarea input with current comment and validation.
 */
export function EditCommentModal({
  isOpen,
  file,
  onClose,
  onSubmit,
  isSubmitting = false,
  error,
}: IEditCommentModalProps) {
  const [comment, setComment] = useState<string>(file?.comment || "");
  const [validationError, setValidationError] = useState<string | null>(null);

  const textareaRef = useRef<HTMLTextAreaElement>(null);

  /**
   * Sync form state when modal opens or file changes.
   */
  useEffect(() => {
    if (isOpen && file && textareaRef.current) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setComment(file.comment || "");
      setValidationError(null);

      requestAnimationFrame(() => {
        textareaRef.current?.focus();
        textareaRef.current?.select();
      });
    }
  }, [isOpen, file]);

  const validateComment = (text: string): string | null => {
    if (text.length > 500) {
      return "Комментарий слишком длинный (максимум 500 символов)";
    }
    if (text === file?.comment) {
      return "Обновляемый комментарий не должно совпадать с исходным";
    }
    return null;
  };

  const handleSubmit = async (): Promise<void> => {
    const validationErr = validateComment(comment);
    if (validationErr) {
      setValidationError(validationErr);
      return;
    }

    setValidationError(null);
    await onSubmit(comment.trim());
    // Modal closes after successful submission (handled by parent)
  };

  const handleInputChange = (value: string): void => {
    setComment(value);
    if (validationError) setValidationError(null);
  };

  const handleClose = (): void => {
    if (!isSubmitting) onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Комментарий к файлу"
      ariaLabel="Редактирование комментария к файлу"
      focusTarget={textareaRef as React.RefObject<HTMLElement>}
      closeOnOverlayClick={!isSubmitting}
      closeOnEsc={!isSubmitting}
      footer={
        <>
          <Button
            variant="secondary"
            onClick={handleClose}
            disabled={isSubmitting}
          >
            <AiOutlineClose />
            Отмена
          </Button>
          <Button
            variant="primary"
            onClick={handleSubmit}
            loading={isSubmitting}
          >
            <FaSave />
            Сохранить
          </Button>
        </>
      }
    >
      <div className="edit-comment-modal">
        <ControlledTextarea
          ref={textareaRef}
          value={comment}
          placeholder="Введите комментарий к файлу"
          label="Комментарий"
          onChange={handleInputChange}
          error={validationError || error || undefined}
          disabled={isSubmitting}
          rows={4}
          maxLength={500}
        />

        <p className="edit-comment-modal__symbol-count">
          {comment.length}/500 символов
        </p>

        {file?.comment && (
          <p className="edit-comment-modal__current">
            Текущий комментарий: <strong>"{file.comment}"</strong>
          </p>
        )}
      </div>
    </Modal>
  );
}
