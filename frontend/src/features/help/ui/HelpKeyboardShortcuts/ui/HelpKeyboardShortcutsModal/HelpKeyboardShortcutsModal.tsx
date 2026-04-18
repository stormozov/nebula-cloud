import { Modal } from "@/shared/ui";

import type { IHelpKeyboardShortcutsModalContent } from "../../lib/types";
import { HelpKeyboardShortcutsList } from "../HelpKeyboardShortcutsList";

import "./HelpKeyboardShortcutsModal.scss";

/**
 * Props interface for the `HelpKeyboardShortcutsModal` component.
 */
export interface IHelpKeyboardShortcutsModalProps {
  /** The content to be displayed within the modal. */
  content: IHelpKeyboardShortcutsModalContent;
  /** Optional CSS class name to be applied to the modal root element. */
  className?: string;
  /** A boolean indicating whether the modal is currently visible. */
  isOpen: boolean;
  /** Callback function triggered when the user requests to close the modal. */
  onClose: () => void;
}

/**
 * A React component that renders a modal dialog displaying keyboard shortcuts
 * in a structured format.
 *
 * @example
 * <HelpKeyboardShortcutsModal
 *   isOpen={true}
 *   content={{
 *     title: "Горячие клавиши",
 *     shortcuts: [
 *       {
 *         title: "Просмотр",
 *         shortcuts: [{ key: "V", description: "Просмотреть файл" }]
 *       }
 *     ]
 *   }}
 *   onClose={() => console.log("Modal closed")}
 * />
 */
export function HelpKeyboardShortcutsModal({
  content,
  className,
  isOpen,
  onClose,
}: IHelpKeyboardShortcutsModalProps) {
  return (
    <Modal
      className={className}
      title={content.title}
      isOpen={isOpen}
      onClose={onClose}
    >
      <p className="help-keyboard-shortcuts-modal__description">
        Клавиатурные комбинации, предназначенные для выполнения операций с
        файлами, не функционируют в отсутствие фокуса на соответствующий файл.
      </p>
      <HelpKeyboardShortcutsList content={content} />
    </Modal>
  );
}
