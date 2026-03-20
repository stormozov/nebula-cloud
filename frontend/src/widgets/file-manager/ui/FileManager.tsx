import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import { useState } from "react";

import type { IFile, IFileRename } from "@/entities/file";
import {
  downloadFileFromApi,
  useDeleteFileMutation,
  useDeletePublicLinkMutation,
  useGeneratePublicLinkMutation,
  useGetFilesQuery,
  useRenameFileMutation,
  useUpdateCommentMutation,
} from "@/entities/file";
import { EditCommentModal } from "@/features/file/file-comment";
import { DeleteFileModal } from "@/features/file/file-delete";
import { ImageViewerModal } from "@/features/file/file-image-preview";
import { FileList } from "@/features/file/file-list";
import { PublicLinkModal } from "@/features/file/file-public-link";
import { RenameFileModal } from "@/features/file/file-rename";
import {
  FileUploadButton,
  FileUploadDropzone,
} from "@/features/file/file-upload";
import { camelToSnake, isImageFile } from "@/shared/utils";

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

  // Mutations
  const [deleteFile, { isLoading: isDeleting }] = useDeleteFileMutation();
  const [renameFile, { isLoading: isRenaming }] = useRenameFileMutation();
  const [updateComment, { isLoading: isUpdatingComment }] =
    useUpdateCommentMutation();
  const [generatePublicLink, { isLoading: isGeneratingLink }] =
    useGeneratePublicLinkMutation();
  const [deletePublicLink, { isLoading: isDeletingLink }] =
    useDeletePublicLinkMutation();

  // Modal states
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [renameModalOpen, setRenameModalOpen] = useState(false);
  const [commentModalOpen, setCommentModalOpen] = useState(false);
  const [linkModalOpen, setLinkModalOpen] = useState(false);
  const [imageViewerOpen, setImageViewerOpen] = useState(false);

  const [selectedImageFile, setSelectedImageFile] = useState<IFile | null>(
    null,
  );
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

  // -- Rename file handlers ---------------------------------------------------

  const handleRename = (file: IFile): void => {
    setSelectedFile(file);
    setRenameModalOpen(true);
  };

  const handleRenameSubmit = async (newName: string): Promise<void> => {
    if (!selectedFile) return;

    try {
      const newFileName = camelToSnake({ original_name: newName });
      await renameFile({
        id: selectedFile.id,
        data: newFileName as IFileRename,
      }).unwrap();
      setRenameModalOpen(false);
      setSelectedFile(null);
    } catch (err) {
      console.error("Failed to rename file:", err);
      // Error is handled by RTK Query onError in fileApi.ts
    }
  };

  const handleRenameClose = (): void => {
    if (isRenaming) return;
    setRenameModalOpen(false);
    setSelectedFile(null);
  };

  // -- Comment handlers -------------------------------------------------------

  const handleEditComment = (file: IFile): void => {
    setSelectedFile(file);
    setCommentModalOpen(true);
  };

  const handleCommentSubmit = async (newComment: string): Promise<void> => {
    if (!selectedFile) return;

    try {
      await updateComment({
        id: selectedFile.id,
        data: { comment: newComment },
      }).unwrap();
      setCommentModalOpen(false);
      setSelectedFile(null);
    } catch (err) {
      console.error("Failed to update comment:", err);
    }
  };

  const handleCommentClose = (): void => {
    if (isUpdatingComment) return;
    setCommentModalOpen(false);
    setSelectedFile(null);
  };

  // -- Download handlers ------------------------------------------------------

  const handleDownload = async (file: IFile): Promise<void> => {
    try {
      await downloadFileFromApi(file.id, file.originalName);
    } catch (err) {
      console.error("Download failed:", err);
    }
  };

  // -- Public link handlers ---------------------------------------------------

  const handlePublicLink = (file: IFile): void => {
    setSelectedFile(file);
    setLinkModalOpen(true);
  };

  const handleGenerateLink = async (): Promise<void> => {
    if (!selectedFile) return;

    try {
      const updatedFile = await generatePublicLink(selectedFile.id).unwrap();
      setSelectedFile(updatedFile);
      // Don't close modal - user might want to copy the link
    } catch (err) {
      console.error("Failed to generate link:", err);
    }
  };

  const handleCopyLink = async (url: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(url);
    } catch (err) {
      console.error("Failed to copy link:", err);
      alert("Не удалось скопировать ссылку");
    }
  };

  const handleDeleteLink = async (): Promise<void> => {
    if (!selectedFile) return;

    try {
      const updatedFile = await deletePublicLink(selectedFile.id).unwrap();

      setSelectedFile(updatedFile);

      setLinkModalOpen(false);
      setSelectedFile(null);
    } catch (err) {
      console.error("Failed to delete link:", err);
    }
  };

  const handleLinkClose = (): void => {
    if (isGeneratingLink && isDeletingLink) return;
    setLinkModalOpen(false);
    setSelectedFile(null);
  };

  // -- View handlers ----------------------------------------------------------

  const handleView = (file: IFile): void => {
    if (isImageFile(file)) {
      setSelectedImageFile(file);
      setImageViewerOpen(true);
      return;
    }
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

      {/* File actions modals */}
      <DeleteFileModal
        isOpen={deleteModalOpen}
        file={selectedFile}
        onConfirm={handleDeleteConfirm}
        onClose={handleDeleteClose}
        isDeleting={isDeleting}
      />
      <RenameFileModal
        key={selectedFile?.id}
        isOpen={renameModalOpen}
        onClose={handleRenameClose}
        file={selectedFile}
        onSubmit={handleRenameSubmit}
        isSubmitting={isRenaming}
      />
      <EditCommentModal
        isOpen={commentModalOpen}
        onClose={handleCommentClose}
        file={selectedFile}
        onSubmit={handleCommentSubmit}
        isSubmitting={isUpdatingComment}
      />
      <PublicLinkModal
        isOpen={linkModalOpen}
        file={selectedFile}
        onGenerate={handleGenerateLink}
        onCopy={handleCopyLink}
        onClose={handleLinkClose}
        onDelete={handleDeleteLink}
        isGenerating={isGeneratingLink}
        isDeleting={isDeletingLink}
      />
      <ImageViewerModal
        isOpen={imageViewerOpen}
        file={selectedImageFile}
        onClose={() => setImageViewerOpen(false)}
      />
    </div>
  );
}
