import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import { useState } from "react";

import type { IFile } from "@/entities/file";
import {
  downloadFileFromApi,
  useDeleteFileMutation,
  useGetFilesQuery,
} from "@/entities/file";
import { DeleteFileModal } from "@/features/file/file-delete";
import { FileList } from "@/features/file/file-list";
import {
  FileUploadButton,
  FileUploadDropzone,
} from "@/features/file/file-upload";
import { getAccessTokenFromPersist } from "@/shared/utils";

import "./FileManager.scss";

/**
 * Props for FileManager widget.
 */
export interface IFileManagerProps {
  /** User ID for admin mode (optional). */
  userId?: number;
  /** Whether current user is admin. */
  isAdmin?: boolean;
  /** Callback when file is selected. */
  onFileSelect?: (file: IFile) => void;
}

/**
 * File manager widget.
 *
 * Combines file list, upload button, and dropzone into a single component.
 * Used on client disk page and admin file management page.
 */
export function FileManager({
  userId,
  isAdmin = false,
  onFileSelect,
}: IFileManagerProps) {
  const { data: files = [], isLoading, error } = useGetFilesQuery();

  const [deleteFile, { isLoading: isDeleting }] = useDeleteFileMutation();

  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<IFile | null>(null);

  const hasFiles = files.length > 0;

  /**
   * Extract error message from RTK Query error object.
   */
  const getErrorMessage = (err: typeof error): string | null => {
    if (!err || typeof err !== "object") return "";

    // RTK Query error can be FetchBaseQueryError or SerializedError
    if ("status" in err) {
      // FetchBaseQueryError (HTTP error)
      const httpError = err as FetchBaseQueryError;
      const data = httpError.data as { detail?: string } | undefined;
      return data?.detail || `Ошибка ${httpError.status}`;
    }

    if ("message" in err) {
      // SerializedError
      return (err as { message?: string }).message || "Неизвестная ошибка";
    }

    // Fallback
    return "Не удалось загрузить файлы";
  };

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  // -- Delete file handlers ---------------------------------------------------

  const handleDelete = (file: IFile): void => {
    setSelectedFile(file);
    setDeleteModalOpen(true);
  };

  const handleDeleteConfirm = async (): Promise<void> => {
    if (!selectedFile) return;

    try {
      await deleteFile(selectedFile.id).unwrap();
      setDeleteModalOpen(false);
      setSelectedFile(null);
    } catch (err) {
      console.error("Failed to delete file:", err);
      // Error is handled by RTK Query onError in fileApi.ts
    }
  };

  const handleDeleteClose = (): void => {
    if (isDeleting) return;
    setDeleteModalOpen(false);
    setSelectedFile(null);
  };

  /**
   * Handle file rename.
   */
  const handleRename = (file: IFile): void => {
    const newName = window.prompt(
      "Введите новое имя файла:",
      file.originalName,
    );
    if (newName && newName !== file.originalName) {
      console.log("Rename file:", file.id, "→", newName);
      // TODO: Integrate with useRenameFileMutation
    }
  };

  /**
   * Handle comment edit.
   */
  const handleEditComment = (file: IFile): void => {
    const newComment = window.prompt(
      "Введите комментарий к файлу:",
      file.comment || "",
    );
    if (newComment !== undefined) {
      console.log("Edit comment:", file.id, "→", newComment);
      // TODO: Integrate with useUpdateCommentMutation
    }
  };

  /**
   * Handle file download.
   */
  const handleDownload = async (file: IFile): Promise<void> => {
    try {
      const accessToken = getAccessTokenFromPersist();
      await downloadFileFromApi(file.id, file.originalName);
      console.log("Download file:", file.id, file.originalName);
    } catch (err) {
      console.error("Download failed:", err);
    }
  };

  /**
   * Handle public link action.
   */
  const handlePublicLink = (file: IFile): void => {
    if (file.hasPublicLink && file.publicLinkUrl) {
      // Copy existing link
      navigator.clipboard.writeText(file.publicLinkUrl).then(
        () => {
          console.log("Public link copied:", file.publicLinkUrl);
          alert("Ссылка скопирована в буфер обмена!");
        },
        () => {
          console.error("Failed to copy link");
          alert("Не удалось скопировать ссылку");
        },
      );
    } else {
      // Generate new link
      const confirmed = window.confirm(
        `Создать публичную ссылку для файла "${file.originalName}"?`,
      );
      if (confirmed) {
        console.log("Generate public link:", file.id);
        // TODO: Integrate with useGeneratePublicLinkMutation
      }
    }
  };

  /**
   * Handle file view.
   */
  const handleView = (file: IFile): void => {
    // Open file in new tab (for viewable types like images, PDFs)
    const accessToken = getAccessTokenFromPersist();
    const viewUrl = `${import.meta.env.VITE_API_BASE_URL || "/api"}/storage/files/${file.id}/download/`;

    // For now, just download the file
    // TODO: Implement proper viewer for images/PDFs
    window.open(viewUrl, "_blank");
    console.log("View file:", file.id, file.originalName);
  };

  // ---------------------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------------------

  return (
    <div className="file-manager">
      <div className="file-manager__toolbar">
        <FileUploadButton variant="primary" size="medium">
          Загрузить файл
        </FileUploadButton>
      </div>

      {/* Dropzone - ONLY WHEN NO FILES */}
      {!hasFiles && !isLoading && (
        <div className="file-manager__dropzone">
          <FileUploadDropzone
            mode="local"
            clickable={true}
            multiple={true}
            comment="Загружено через FileManager"
          />
        </div>
      )}

      {/* File list */}
      {hasFiles && (
        <div className="file-manager__list">
          <FileList
            files={files}
            isLoading={isLoading}
            error={getErrorMessage(error)}
            emptyMessage={
              hasFiles
                ? "Файлы не найдены"
                : "В хранилище нет файлов. Загрузите первый файл!"
            }
            onSelectFile={onFileSelect}
            onViewFile={handleView}
            onDownloadFile={handleDownload}
            onPublicLinkFile={handlePublicLink}
            onRenameFile={handleRename}
            onEditCommentFile={handleEditComment}
            onDeleteFile={handleDelete}
          />
        </div>
      )}

      {/* Delete Modal */}
      <DeleteFileModal
        isOpen={deleteModalOpen}
        file={selectedFile}
        onConfirm={handleDeleteConfirm}
        onClose={handleDeleteClose}
        isDeleting={isDeleting}
      />
    </div>
  );
}
