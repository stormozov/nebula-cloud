import { memo } from "react";
import type { IFileListBodyProps } from "../lib/types";
import { FileListItem } from "./FileListItem";

export function FileListBodyPlain({
  files,
  disabled = false,
  onSelect,
  onView,
  onDownload,
  onPublicLink,
  onRename,
  onEditComment,
  onDelete,
}: IFileListBodyProps) {
  return (
    <tbody className="file-list__body">
      {files.map((file) => (
        <FileListItem
          key={file.id}
          file={file}
          disabled={disabled}
          onSelect={onSelect}
          onView={onView}
          onDownload={onDownload}
          onPublicLink={onPublicLink}
          onRename={onRename}
          onEditComment={onEditComment}
          onDelete={onDelete}
        />
      ))}
    </tbody>
  );
}

/**
 * Renders the body of a file list by mapping over an array of files
 * and creating a FileListItem for each.
 */
export const FileListBody = memo(FileListBodyPlain);
