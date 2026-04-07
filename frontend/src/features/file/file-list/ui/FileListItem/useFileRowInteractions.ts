import { useCallback, useState } from "react";

import type { IFile } from "@/entities/file";
import type { IContextMenuState, IDropdownMenuActionItem } from "@/shared/ui";

import type { IFileHandlersProps } from "../../lib/types";

const initialContextMenuState: IContextMenuState = {
  isOpen: false,
  position: { x: 0, y: 0 },
};

/**
 * Properties for the `useFileRowInteractions` hook.
 */
interface IUseFileRowInteractionsProps {
  file: IFile;
  handlers: IFileHandlersProps;
  actions: IDropdownMenuActionItem<IFile>[];
  disabled?: boolean;
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
  const [contextMenu, setContextMenu] = useState<IContextMenuState>(
    initialContextMenuState,
  );

  const handleRowClick = useCallback(() => {
    if (!disabled && onSelect) onSelect(file);
  }, [disabled, onSelect, file]);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect?.(file);
      handlers.onView?.(file);
    }

    if (event.key === "Delete") {
      event.preventDefault();
      handlers.onDelete?.(file);
    }

    if (event.key === "r" || event.key === "F2") {
      event.preventDefault();
      handlers.onRename?.(file);
    }

    if (event.key === "c") {
      event.preventDefault();
      handlers.onEditComment?.(file);
    }

    if (event.key === "l") {
      event.preventDefault();
      handlers.onPublicLink?.(file);
    }

    if (event.key === "v") {
      event.preventDefault();
      handlers.onDownload?.(file);
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
