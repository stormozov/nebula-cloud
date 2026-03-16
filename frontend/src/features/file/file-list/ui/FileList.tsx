import fileListConfig from "@/shared/configs/file-list.json";

import type { IFileListProps } from "../lib/types";
import { FileListBody } from "./FileListBody";
import { FileListHeader } from "./FileListHeader";

import "./FileList.scss";

/**
 * A component that renders a list of files in a tabular format with support
 * for loading, error, and empty states.
 */
export function FileList({
  files,
  isLoading = false,
  error = null,
  emptyMessage = "Файлы не загружены",
  onSelectFile,
  onViewFile,
  onDownloadFile,
  onPublicLinkFile,
  onRenameFile,
  onEditCommentFile,
  onDeleteFile,
}: IFileListProps) {
  if (isLoading) {
    return (
      <div className="file-list file-list--loading" aria-live="polite">
        <div className="file-list__loader">Загрузка файлов...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="file-list file-list--error" role="alert">
        <div className="file-list__error">{error}</div>
      </div>
    );
  }

  if (files.length === 0) {
    return (
      <div className="file-list file-list--empty">
        <div className="file-list__empty">{emptyMessage}</div>
      </div>
    );
  }

  return (
    <div className="file-list">
      <table className="file-list__table">
        <FileListHeader columns={fileListConfig.header_columns} />
        <FileListBody
          files={files}
          onSelect={onSelectFile}
          onView={onViewFile}
          onDownload={onDownloadFile}
          onPublicLink={onPublicLinkFile}
          onRename={onRenameFile}
          onEditComment={onEditCommentFile}
          onDelete={onDeleteFile}
        />
      </table>
    </div>
  );
}
