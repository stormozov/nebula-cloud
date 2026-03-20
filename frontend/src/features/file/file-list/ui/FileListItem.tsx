import { memo, useState } from "react";

import { FileIcon } from "@/shared/ui";
import {
  formatDate,
  formatFileSize,
  truncateWithMiddleEllipsis,
} from "@/shared/utils";

import type { IFileListItemProps } from "../lib/types";
import { FileItemActions } from "./FileItemActions";

import "./FileListItem.scss";

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
  const [showActions, setShowActions] = useState(false);

  const handleMouseEnter = () => {
    if (!disabled) setShowActions(true);
  };

  const handleMouseLeave = () => {
    setShowActions(false);
  };

  const handleClick = () => {
    if (!disabled && onSelect) onSelect(file);
  };

  return (
    <tr
      className="file-list-item"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
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
          title={truncateWithMiddleEllipsis(file.comment || "Нет комментария")}
        >
          {truncateWithMiddleEllipsis(file.comment || "—", 35, 3, 2)}
        </span>
      </td>

      <td className="file-list-item__cell file-list-item__cell--size">
        {formatFileSize(file.size)}
      </td>

      <td className="file-list-item__cell file-list-item__cell--uploaded">
        {formatDate(file.uploadedAt)}
      </td>

      <td className="file-list-item__cell file-list-item__cell--downloaded">
        {formatDate(file.lastDownloaded)}
      </td>

      <td className="file-list-item__cell file-list-item__cell--actions">
        <FileItemActions
          file={file}
          isVisible={showActions}
          disabled={disabled}
          onView={onView}
          onDownload={onDownload}
          onPublicLink={onPublicLink}
          onRename={onRename}
          onEditComment={onEditComment}
          onDelete={onDelete}
        />
      </td>
    </tr>
  );
}

/**
 * A component that renders a single row in a file list, displaying file
 * metadata and providing interactive actions.
 */
export const FileListItem = memo(FileListItemPlain, (prevProps, nextProps) => {
  return (
    prevProps.file.id === nextProps.file.id &&
    prevProps.file.originalName === nextProps.file.originalName &&
    prevProps.file.size === nextProps.file.size &&
    prevProps.file.comment === nextProps.file.comment &&
    prevProps.disabled === nextProps.disabled
  );
});
