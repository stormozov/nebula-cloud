import { memo, useCallback, useState } from "react";

import { DropdownMenu, FileIcon, type IContextMenuState } from "@/shared/ui";
import {
  formatDate,
  formatFileSize,
  truncateWithMiddleEllipsis,
} from "@/shared/utils";

import type { IFileListItemProps } from "../lib/types";
import { useFileActions } from "../lib/useFileActions";

import "./FileListItem.scss";

const initialContextMenuState: IContextMenuState = {
  isOpen: false,
  position: { x: 0, y: 0 },
};

export function FileListItemPlain({
  file,
  disabled = false,
  onSelect,
  onView,
  onDownload,
  onPublicLink,
  onRename,
  onEditComment,
  onDelete,
}: IFileListItemProps) {
  const [contextMenu, setContextMenu] = useState<IContextMenuState>(
    initialContextMenuState,
  );

  const actions = useFileActions({
    file,
    onView,
    onDownload,
    onPublicLink,
    onRename,
    onEditComment,
    onDelete,
  });

  const handleRowClick = useCallback(() => {
    if (!disabled && onSelect) onSelect(file);
  }, [disabled, onSelect, file]);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect?.(file);
      onView?.(file);
    }

    if (event.key === "Delete") {
      event.preventDefault();
      onDelete?.(file);
    }

    if (event.key === "r" || event.key === "F2") {
      event.preventDefault();
      onRename?.(file);
    }
    
    if (event.key === "c") {
      event.preventDefault();
      onEditComment?.(file);
    }

    if (event.key === "l") {
      event.preventDefault();
      onPublicLink?.(file);
    };

    if (event.key === "v") {
      event.preventDefault();
      onDownload?.(file);
    };
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

  return (
    <>
      <tr
        className="file-list-item"
        onClick={handleRowClick}
        onDoubleClick={() => onView?.(file)}
        onKeyDown={handleKeyDown}
        onContextMenu={handleContextMenu}
        tabIndex={disabled ? -1 : 0}
        aria-selected={false}
      >
        <td className="file-list-item__cell file-list-item__cell--icon">
          <FileIcon filename={file.originalName} size={32} />
        </td>

        <td className="file-list-item__cell file-list-item__cell--name">
          <span className="file-list-item__name" title={file.originalName}>
            {truncateWithMiddleEllipsis(file.originalName)}
          </span>
        </td>

        <td className="file-list-item__cell file-list-item__cell--comment">
          <span
            className="file-list-item__comment"
            title={truncateWithMiddleEllipsis(
              file.comment || "Нет комментария",
            )}
          >
            {file.comment || "—"}
          </span>
        </td>

        <td className="file-list-item__cell file-list-item__cell--size">
          {formatFileSize(file.size)}
        </td>

        <td
          className="file-list-item__cell file-list-item__cell--uploaded"
          title={file.uploadedAt}
        >
          {formatDate(file.uploadedAt)}
        </td>

        <td
          className="file-list-item__cell file-list-item__cell--downloaded"
          title={file.lastDownloaded || "Еще не был скачан"}
        >
          {formatDate(file.lastDownloaded)}
        </td>

        <td className="file-list-item__cell file-list-item__cell--actions">
          {actions.length > 0 && (
            <DropdownMenu
              triggerButtonProps={{
                icon: { name: "more" },
                variant: "secondary",
                size: "small",
                className: "file-list-item__actions-button",
                "aria-label": "Действия с файлом",
              }}
              actions={actions}
              item={file}
              placement="bottom-end"
            />
          )}
        </td>
      </tr>
      {actions.length > 0 && (
        <DropdownMenu
          actions={actions}
          item={file}
          position={contextMenu.isOpen ? contextMenu.position : undefined}
          isOpen={contextMenu.isOpen}
          onOpenChange={(open) => !open && handleContextMenuClose()}
          placement="bottom-start"
          closeOnClickOutside
          closeOnEscape
        />
      )}
    </>
  );
}

/**
 * A component that renders a single row in a file list, displaying file
 * metadata and providing interactive actions via dropdown menu.
 */
export const FileListItem = memo(FileListItemPlain, (prevProps, nextProps) => {
  return (
    prevProps.file.id === nextProps.file.id &&
    prevProps.file.originalName === nextProps.file.originalName &&
    prevProps.file.size === nextProps.file.size &&
    prevProps.file.comment === nextProps.file.comment &&
    prevProps.file.hasPublicLink === nextProps.file.hasPublicLink &&
    prevProps.disabled === nextProps.disabled &&
    prevProps.onView === nextProps.onView &&
    prevProps.onDownload === nextProps.onDownload &&
    prevProps.onPublicLink === nextProps.onPublicLink &&
    prevProps.onRename === nextProps.onRename &&
    prevProps.onEditComment === nextProps.onEditComment &&
    prevProps.onDelete === nextProps.onDelete
  );
});
