import { useCallback, useState } from "react";

import type { IFile } from "@/entities/file";
import type { DropdownMenuItem, IContextMenuState } from "@/shared/ui";

import type { IFileHandlersProps } from "../../lib/types";

const INIT_CONTEXT_STATE: IContextMenuState = {
  isOpen: false,
  position: { x: 0, y: 0 },
};

/**
 * Properties for the `useFileRowInteractions` hook.
 */
interface IUseFileRowInteractionsProps {
  /** The file to be interacted with */
  file: IFile;
  /** Handlers for file actions */
  handlers: IFileHandlersProps;
  /** Actions to be displayed in the context menu */
  actions: DropdownMenuItem<IFile>[];
  /** Whether the row is disabled */
  disabled?: boolean;
  /** Callback to be called when the row is selected */
  onSelect?: (file: IFile) => void;
}

/**
 * Custom hook for handling row interactions in the file list.
 */
export const useFileRowInteractions = ({
  file,
  handlers,
  actions,
  disabled,
  onSelect,
}: IUseFileRowInteractionsProps) => {
  const [contextMenu, setContextMenu] =
    useState<IContextMenuState>(INIT_CONTEXT_STATE);

  const handleRowClick = useCallback(() => {
    if (!disabled && onSelect) onSelect(file);
  }, [disabled, onSelect, file]);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect?.(file);
      handlers.onView?.(file);
    } else if (
      (event.ctrlKey && event.key === "s") ||
      (event.metaKey && event.key === "s")
    ) {
      event.preventDefault();
      handlers.onDownload?.(file);
    } else if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      handlers.onDelete?.(file);
    } else if (event.shiftKey && event.key === "F2") {
      event.preventDefault();
      handlers.onEditComment?.(file);
    } else if (event.key === "F2") {
      event.preventDefault();
      handlers.onRename?.(file);
    } else if (
      (event.ctrlKey && event.key === "l") ||
      (event.metaKey && event.key === "l")
    ) {
      event.preventDefault();
      handlers.onPublicLink?.(file);
    }
  };

  const handleContextMenu = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      if (actions.length === 0) return;
      setContextMenu({
        isOpen: true,
        position: { x: e.clientX, y: e.clientY },
      });
    },
    [actions.length],
  );

  const handleContextMenuClose = useCallback(() => {
    setContextMenu((prev) => ({ ...prev, isOpen: false }));
  }, []);

  return {
    contextMenu,
    handleContextMenu,
    handleContextMenuClose,
    handleRowClick,
    handleKeyDown,
  };
};
