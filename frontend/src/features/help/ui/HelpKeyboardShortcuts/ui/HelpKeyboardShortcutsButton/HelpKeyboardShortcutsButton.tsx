import { useCallback, useMemo, useState } from "react";

import { Button, type IButtonProps } from "@/shared/ui";

import { DEFAULT_MODAL_TITLE } from "../../lib/constants";
import {
  DEFAULT_CONTEXT,
  type KeyboardShortcutContext,
  keyboardShortcuts,
} from "../../lib/keyboardShortcuts";
import type { IHelpKeyboardShortcutsModalContent } from "../../lib/types";
import { prepareShortcuts } from "../../lib/utils";
import { HelpKeyboardShortcutsModal } from "../HelpKeyboardShortcutsModal";

/**
 * Props interface for the `HelpKeyboardShortcutsButton` component.
 */
export interface IHelpKeyboardShortcutsButtonProps {
  /**
   * Optional context key used to fetch default keyboard shortcuts from
   * the global `keyboardShortcuts` registry.
   *
   * @example "editor", "viewer", "file-manager"
   */
  context?: KeyboardShortcutContext;
  /** Optional array of shortcut entries to display in the modal. */
  shortcuts?: IHelpKeyboardShortcutsModalContent["shortcuts"];
  /** Optional title for the modal dialog. */
  modalTitle?: string;
  /** Optional CSS class name to be applied to the modal root element. */
  modalClassName?: string;
  /** Additional props to pass down to the underlying `Button` component. */
  buttonProps?: IButtonProps;
  /** Optional content to render inside the button. */
  children?: React.ReactNode;
}

/**
 * A React component that renders a button to open a modal displaying keyboard
 * shortcuts.
 *
 * @example
 * <HelpKeyboardShortcutsButton context="editor" modalTitle="Editor Shortcuts" />
 *
 * @example
 * <HelpKeyboardShortcutsButton shortcuts={customShortcuts}>
 *   Show Custom Help
 * </HelpKeyboardShortcutsButton>
 */
export function HelpKeyboardShortcutsButton({
  context = DEFAULT_CONTEXT,
  shortcuts: externalShortcuts,
  modalTitle: title = DEFAULT_MODAL_TITLE,
  modalClassName = "help-keyboard-shortcuts-modal",
  buttonProps,
  children,
}: IHelpKeyboardShortcutsButtonProps) {
  const [isOpen, setIsOpen] = useState(false);

  const handleOpen = useCallback(() => setIsOpen(true), []);
  const handleClose = useCallback(() => setIsOpen(false), []);

  const shortcuts = useMemo(() => {
    if (externalShortcuts !== undefined) return externalShortcuts;
    const contextData = keyboardShortcuts[context];
    return prepareShortcuts(contextData);
  }, [context, externalShortcuts]);

  const modalContent = useMemo(
    () => ({ title, shortcuts }),
    [title, shortcuts],
  );

  return (
    <>
      <Button
        variant="primary"
        icon={{ name: "keyboard" }}
        title="Показать справку по клавишам"
        aria-label="Показать справку по клавишам"
        {...buttonProps}
        onClick={handleOpen}
      >
        {children}
      </Button>
      {isOpen && (
        <HelpKeyboardShortcutsModal
          content={modalContent}
          className={modalClassName}
          isOpen={isOpen}
          onClose={handleClose}
        />
      )}
    </>
  );
}
