import { memo } from "react";

import { DropdownMenu, FileIcon } from "@/shared/ui";
import {
  formatDate,
  formatFileSize,
  truncateWithMiddleEllipsis,
} from "@/shared/utils";

import type { IFileListItemProps } from "../../lib/types";
import { useFileActions } from "../../lib/useFileActions";
import { useFileRowInteractions } from "./useFileRowInteractions";

import "./FileListItem.scss";

export function FileListItemPlain({
  file,
  disabled = false,
  onSelect,
  handlers = {},
}: IFileListItemProps) {
  const actions = useFileActions({ file, handlers });
  const {
    contextMenu,
    handleRowClick,
    handleKeyDown,
    handleContextMenu,
    handleContextMenuClose,
  } = useFileRowInteractions({ file, handlers, actions, disabled, onSelect });

  return (
    <>
      <tr
        className="file-list-item"
        onClick={handleRowClick}
        onDoubleClick={() => handlers.onView?.(file)}
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
              items={actions}
              item={file}
              placement="bottom-end"
            />
          )}
        </td>
      </tr>
      {actions.length > 0 && (
        <DropdownMenu
          items={actions}
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
    prevProps.handlers?.onView === nextProps.handlers?.onView &&
    prevProps.handlers?.onDownload === nextProps.handlers?.onDownload &&
    prevProps.handlers?.onPublicLink === nextProps.handlers?.onPublicLink &&
    prevProps.handlers?.onRename === nextProps.handlers?.onRename &&
    prevProps.handlers?.onEditComment === nextProps.handlers?.onEditComment &&
    prevProps.handlers?.onDelete === nextProps.handlers?.onDelete
  );
});
