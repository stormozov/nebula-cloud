import { useEffect, useRef } from "react";

import type { IFile } from "@/entities/file";

import type { IFileHandlersProps } from "./types";

/**
 * Properties for the `useFileListKeyboardShortcuts` hook.
 */
interface IUseFileListKeyboardShortcutsProps {
  /** Array of file objects currently displayed in the list. */
  files: IFile[];
  /** Handlers for file actions. */
  handlers: IFileHandlersProps;
}

/**
 * Attaches a global `window` keydown listener for file-manager keyboard
 * shortcuts that are reserved by the browser (`CTRL + S`, `CTRL + L`).
 *
 * These shortcuts cannot be intercepted at the element level (e.g. on a
 * table row) because the browser processes them on `window` / `document`
 * before the event ever reaches individual DOM elements.  The hook therefore
 * listens globally, determines which row currently has focus via
 * `data-file-id`, and calls the corresponding action handler.
 */
export const useFileListKeyboardShortcuts = ({
  files,
  handlers,
}: IUseFileListKeyboardShortcutsProps): void => {
  const filesRef = useRef(files);
  const handlersRef = useRef(handlers);

  useEffect(() => {
    filesRef.current = files;
    handlersRef.current = handlers;
  });

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      const activeElement = document.activeElement;
      if (!activeElement) return;

      const tagName = activeElement.tagName;
      const isTyping =
        tagName === "INPUT" ||
        tagName === "TEXTAREA" ||
        activeElement.getAttribute("contenteditable") === "true";

      if (isTyping) return;

      const row = activeElement.closest(".file-list__body [data-file-id]");
      if (!row) return;

      const fileId = row.getAttribute("data-file-id");
      if (!fileId) return;

      const file = filesRef.current.find((f) => String(f.id) === fileId);
      if (!file) return;

      const key = event.key.toLowerCase();
      const code = event.code;
      const isCtrlOrMeta = event.ctrlKey || event.metaKey;

      if (isCtrlOrMeta && (key === "s" || code === "KeyS")) {
        event.preventDefault();
        event.stopImmediatePropagation();
        handlersRef.current.onDownload?.(file);
      } else if (isCtrlOrMeta && (key === "l" || code === "KeyL")) {
        event.preventDefault();
        event.stopImmediatePropagation();
        handlersRef.current.onPublicLink?.(file);
      }
    };

    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, []);
};
