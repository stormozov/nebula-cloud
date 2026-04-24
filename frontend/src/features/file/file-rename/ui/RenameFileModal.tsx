import { useEffect, useRef, useState } from "react";

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

  const validateFileName = (name: string): string | null => {
    if (!name.trim()) {
      return "Имя файла не может быть пустым";
    }
    if (name.length > 255) {
      return "Имя файла слишком длинное (максимум 255 символов)";
    }
    if (name === file?.originalName) {
      return "Обновляемое имя не должно совпадать с исходным";
    }
    return null;
  };

  const handleSubmit = async (): Promise<void> => {
    const validationErr = validateFileName(newFileName);
    if (validationErr) {
      setValidationError(validationErr);
      return;
    }

    setValidationError(null);
    await onSubmit(newFileName.trim());
  };

  const handleKeyDown = (
    event: React.KeyboardEvent<HTMLInputElement>,
  ): void => {
    if (event.key === "Enter" && !isSubmitting) {
      event.preventDefault();
      handleSubmit();
    }
  };

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
            icon={{ name: "close" }}
            disabled={isSubmitting}
            onClick={handleClose}
          >
            Отмена
          </Button>
          <Button
            variant="primary"
            icon={{ name: "save" }}
            loading={isSubmitting}
            onClick={handleSubmit}
          >
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

        <p className="rename-file-modal__symbol-count">
          {newFileName.length}/255 символов
        </p>

        <p className="rename-file-modal__current">
          Текущее имя: <strong>{file?.originalName}</strong>
        </p>
      </div>
    </Modal>
  );
}
