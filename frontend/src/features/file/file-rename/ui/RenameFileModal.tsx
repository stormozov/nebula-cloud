import { useEffect, useRef, useState } from "react";
import { AiOutlineClose } from "react-icons/ai";
import { FaSave } from "react-icons/fa";

import type { IFile } from "@/entities/file";
import { Button, ControlledInput } from "@/shared/ui";
import { Modal } from "@/shared/ui/Modal";

import "./RenameFileModal.scss";

/**
 * Props for RenameFileModal component.
 */
export interface IRenameFileModalProps {
  /** Whether modal is visible. */
  isOpen: boolean;
  /** File to rename. */
  file: IFile | null;
  /** Callback when modal should be closed. */
  onClose: () => void;
  /** Callback when rename is submitted. */
  onSubmit: (newName: string) => void | Promise<void>;
  /** Whether rename is in progress. */
  isSubmitting?: boolean;
  /** Error message. */
  error?: string | null;
}

/**
 * Modal for renaming a file.
 *
 * Shows input field with current file name and validation.
 */
export function RenameFileModal({
  isOpen,
  file,
  onClose,
  onSubmit,
  isSubmitting = false,
  error,
}: IRenameFileModalProps) {
  const [newFileName, setNewFileName] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  // Input ref (dual: HTMLElement for Modal, InputElement for ControlledInput)
  const inputRef = useRef<HTMLInputElement>(null);

  // Init editable name on file change (safe with useLayoutEffect)
  // Reset form when modal opens with new file
  useEffect(() => {
    if (isOpen && file && inputRef.current) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNewFileName(file.originalName);
      setValidationError(null);
      // Focus + select all text for UX
      requestAnimationFrame(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    }
  }, [isOpen, file]);

  /**
   * Validate file name.
   */
  const validateFileName = (name: string): string | null => {
    if (!name.trim()) {
      return "Имя файла не может быть пустым";
    }
    if (name.length > 255) {
      return "Имя файла слишком длинное (максимум 255 символов)";
    }
    if (name === file?.originalName) {
      return "Имя файла не должно совпадать с исходным";
    }
    return null;
  };

  /**
   * Handle form submission.
   */
  const handleSubmit = async (): Promise<void> => {
    const validationErr = validateFileName(newFileName);
    if (validationErr) {
      setValidationError(validationErr);
      return;
    }

    setValidationError(null);
    await onSubmit(newFileName.trim());
    // Modal closes after successful submission (handled by parent)
  };

  /**
   * Handle input change.
   */
  // onChange now directly updates state via ControlledInput

  /**
   * Handle key down (Enter to submit).
   */
  const handleKeyDown = (
    event: React.KeyboardEvent<HTMLInputElement>,
  ): void => {
    if (event.key === "Enter" && !isSubmitting) {
      event.preventDefault();
      handleSubmit();
    }
  };

  /**
   * Handle close modal.
   */
  const handleClose = (): void => {
    if (!isSubmitting) onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Переименование файла"
      ariaLabel="Переименование файла"
      focusTarget={inputRef as React.RefObject<HTMLElement>}
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
      <div className="rename-file-modal">
        <ControlledInput
          ref={inputRef}
          type="text"
          value={newFileName}
          onChange={setNewFileName}
          onKeyDown={handleKeyDown}
          placeholder="Введите новое имя файла"
          label="Имя файла"
          error={validationError || error || undefined}
          autoComplete="off"
          disabled={isSubmitting}
        />

        <p className="rename-file-modal__hint">
          Текущее имя: <strong>{file?.originalName}</strong>
        </p>
      </div>
    </Modal>
  );
}
