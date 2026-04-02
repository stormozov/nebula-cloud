import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import { useEffect, useState } from "react";

import { useAppSelector } from "@/app/store/hooks";
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
import { selectIsQueueCompleted } from "@/entities/file-upload";
import { EditCommentModal } from "@/features/file/file-comment";
import { DeleteFileModal } from "@/features/file/file-delete";
import { ImageViewerModal } from "@/features/file/file-image-preview";
import { FileList } from "@/features/file/file-list";
import { PublicLinkModal } from "@/features/file/file-public-link";
import { RenameFileModal } from "@/features/file/file-rename";
import { FileSearchInput, useFileSearch } from "@/features/file/file-search";
import {
  FileUploadButton,
  FileUploadDropzone,
} from "@/features/file/file-upload";
import { isError401 } from "@/shared/api";
import { BackButton, Button, Heading, Icon, PageWrapper } from "@/shared/ui";
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
  // States
  const [currentPage, setCurrentPage] = useState(1);
  const [loadedFiles, setLoadedFiles] = useState<IFile[]>([]);

  const { searchTerm, setSearchTerm, debouncedSearchTerm } = useFileSearch();

  // Queries
  const { data, isLoading, error, isFetching } = useGetFilesQuery(
    userId
      ? {
          userId,
          page: currentPage,
          search: debouncedSearchTerm || undefined,
        }
      : {
          page: currentPage,
          search: debouncedSearchTerm || undefined,
        },
  );

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

  // Listen for upload completion to reset pagination
  const isUploadQueueCompleted = useAppSelector(selectIsQueueCompleted);

  /**
   * Extract error message from RTK Query error object.
   */
  const getErrorMessage = (err: typeof error): string | null => {
    if (!err || typeof err !== "object") return "";

    // RTK Query error can be FetchBaseQueryError or SerializedError
    if ("status" in err) {
      // FetchBaseQueryError (HTTP error)
      const httpError = err as FetchBaseQueryError;
      if (httpError.status === 401) return null;
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
      if (isError401(err as FetchBaseQueryError)) return;
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
      await renameFile({
        id: selectedFile.id,
        data: camelToSnake({ original_name: newName }) as IFileRename,
      }).unwrap();
      setRenameModalOpen(false);
      setSelectedFile(null);
    } catch (err) {
      if (isError401(err as FetchBaseQueryError)) return;
      console.error("Failed to rename file:", err);
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
      if (isError401(err as FetchBaseQueryError)) return;
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
      if (isError401(err as FetchBaseQueryError)) return;
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
      await generatePublicLink(selectedFile.id).unwrap();
      setSelectedFile(selectedFile); // Trigger re-render with cache update
    } catch (err) {
      if (isError401(err as FetchBaseQueryError)) return;
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
      await deletePublicLink(selectedFile.id).unwrap();
      setLinkModalOpen(false);
      setSelectedFile(null);
    } catch (err) {
      if (isError401(err as FetchBaseQueryError)) return;
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

  // -- Load more handlers -----------------------------------------------------

  const loadMore = () => {
    setCurrentPage((prev) => prev + 1);
  };

  // -- Search handlers --------------------------------------------------------

  const handleSearchChange = (value: string) => {
    setSearchTerm(value);
    setCurrentPage(1);
  };

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  // Reset pagination when uploads complete (new files at top of page 1)
  useEffect(() => {
    if (!isUploadQueueCompleted) return;
    window.scrollTo({ top: 0, behavior: "smooth" });
    setTimeout(() => {
      setCurrentPage(1);
      setLoadedFiles([]);
    });
  }, [isUploadQueueCompleted]);

  // Load more files when scrolling to bottom
  useEffect(() => {
    if (!data) return;

    if (currentPage === 1) {
      setTimeout(() => setLoadedFiles(data.results));
    } else {
      setTimeout(() => {
        setLoadedFiles((prev) => {
          const existingIds = new Set(prev.map((f) => f.id));
          const newFiles = data.results.filter((f) => !existingIds.has(f.id));
          return [...prev, ...newFiles];
        });
      });
    }
  }, [data, currentPage]);

  // ---------------------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------------------

  return (
    <div className="file-manager">
      <header className="file-manager__header">
        {!isAdmin ? (
          <>
            <Heading level={2} noMargin className="file-manager__header-title">
              Ваш диск
            </Heading>
            <PageWrapper>
              <FileSearchInput
                inputProps={{
                  value: searchTerm,
                  placeholder: "Поиск по названию и дате загрузки",
                  onChange: handleSearchChange,
                }}
              />
              <FileUploadButton>Загрузить файл</FileUploadButton>
            </PageWrapper>
          </>
        ) : (
          <>
            <PageWrapper>
              <BackButton />
              <Heading
                level={2}
                noMargin
                className="file-manager__header-title"
              >
                Файлы пользователя{" "}
                <sup
                  className="file-manager__header-title-badge"
                  title={`ID пользователя: ${userId}`}
                >
                  <Icon name="person" />
                  {userId}
                </sup>
              </Heading>
            </PageWrapper>
            <FileSearchInput
              buttonProps={{
                children: "Поиск",
                size: "small",
              }}
              inputProps={{
                value: searchTerm,
                placeholder: "Поиск по названию и дате загрузки",
                onChange: handleSearchChange,
              }}
            />
          </>
        )}
      </header>

      {/* Dropzone - ONLY WHEN NO FILES or initial load */}
      {!isAdmin &&
        !debouncedSearchTerm &&
        (!data || data.results.length === 0) &&
        !error &&
        !isLoading &&
        !isFetching && (
          <div className="file-manager__dropzone">
            <FileUploadDropzone
              mode="local"
              clickable={true}
              multiple={true}
              comment="Загружено через FileManager"
            />
          </div>
        )}

      {/* Empty state */}
      {!isLoading &&
        !isFetching &&
        (!data || data.results.length === 0) &&
        !error &&
        (isAdmin || !!debouncedSearchTerm) && (
          <div className="file-manager__empty-message">
            <p>Нет загруженных файлов</p>
          </div>
        )}

      {/* File list */}
      {loadedFiles.length > 0 && (
        <div className="file-manager__list">
          <FileList
            files={loadedFiles}
            isLoading={isLoading}
            error={getErrorMessage(error)}
            emptyMessage="Файлы не найдены"
            onSelectFile={onFileSelect}
            onViewFile={handleView}
            onDownloadFile={handleDownload}
            onPublicLinkFile={handlePublicLink}
            onRenameFile={handleRename}
            onEditCommentFile={handleEditComment}
            onDeleteFile={handleDelete}
          />
          {data?.next && (
            <div className="file-manager__load-more">
              <Button
                icon={{ name: "retry" }}
                loading={isFetching}
                disabled={isFetching}
                onClick={loadMore}
              >
                Загрузить ещё
              </Button>
            </div>
          )}
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
