import { useCallback, useEffect, useMemo } from "react";

import { useAppSelector } from "@/app/store/hooks";
import type { IFile } from "@/entities/file";
import { selectIsQueueCompleted } from "@/entities/file-upload";
import { EditCommentModal } from "@/features/file/file-comment";
import { DeleteFileModal } from "@/features/file/file-delete";
import { ImageViewerModal } from "@/features/file/file-image-preview";
import type { IFileListProps } from "@/features/file/file-list";
import { PublicLinkModal } from "@/features/file/file-public-link";
import { RenameFileModal } from "@/features/file/file-rename";
import { useFileSearch } from "@/features/file/file-search";
import fileListConfig from "@/shared/configs/file-list.json";
import { getErrorMessage, isImageFile } from "@/shared/utils";

import { useFileManagerActions } from "../lib/hooks/useFileManagerActions";
import { useFileManagerModals } from "../lib/hooks/useFileManagerModals";
import { useFileManagerPagination } from "../lib/hooks/useFileManagerPagination";
import { FileManagerContent } from "./FileManagerContent";
import { FileManagerDropzone } from "./FileManagerDropzone";
import { FileManagerHeader } from "./FileManagerHeader";

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
 * Main File Manager component that orchestrates file display, search, upload,
 * and management actions.
 *
 * @example
 * <FileManager userId={123} isAdmin={true} onFileSelect={handleFileSelect} />
 */
export function FileManager({
  userId,
  isAdmin = false,
  onFileSelect,
}: IFileManagerProps) {
  const { searchTerm, setSearchTerm, debouncedSearchTerm } = useFileSearch();

  const {
    files,
    isLoading,
    isFetching,
    error,
    hasNextPage,
    loadMore,
    resetPagination,
  } = useFileManagerPagination({
    userId,
    searchTerm: debouncedSearchTerm,
  });

  const {
    modalOpen,
    selectedFile,
    selectedImageFile,
    openModal,
    closeModal,
    setSelectedImageFile,
    updateSelectedFile,
  } = useFileManagerModals();

  const {
    isDeleting,
    isRenaming,
    isUpdatingComment,
    isGeneratingLink,
    isDeletingLink,
    handleDeleteConfirm,
    handleRenameSubmit,
    handleCommentUpdate,
    handleDownloadFile,
    handleGeneratePublicLink,
    handleDeletePublicLink,
    handleCopyPublicLink,
  } = useFileManagerActions({
    selectedFile,
    closeModal,
  });

  // Listen for upload completion to reset pagination
  const isUploadQueueCompleted = useAppSelector(selectIsQueueCompleted);

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  // -- View handlers ----------------------------------------------------------

  const handleView = useCallback(
    (file: IFile): void => {
      if (!isImageFile(file)) return;
      setSelectedImageFile(file);
      openModal("imageViewer", file);
    },
    [setSelectedImageFile, openModal],
  );

  // -- Search handlers --------------------------------------------------------

  const handleSearchChange = useCallback(
    (value: string) => {
      setSearchTerm(value);
      resetPagination();
    },
    [setSearchTerm, resetPagination],
  );

  // ---------------------------------------------------------------------------
  // PREPARE DATA FOR LIST
  // ---------------------------------------------------------------------------

  const preparedListData = useMemo<IFileListProps>(
    () => ({
      files: files || [],
      states: {
        isLoading: isLoading || isFetching,
        error: getErrorMessage(error),
        emptyMessage: "Нет загруженных файлов",
      },
      handlers: {
        onView: handleView,
        onDownload: handleDownloadFile,
        onPublicLink: (file: IFile) => openModal("link", file),
        onRename: (file: IFile) => openModal("rename", file),
        onEditComment: (file: IFile) => openModal("comment", file),
        onDelete: (file: IFile) => openModal("delete", file),
      },
      headers: fileListConfig.header_columns,
      onSelectFile: onFileSelect,
    }),
    [
      files,
      isLoading,
      isFetching,
      error,
      handleView,
      handleDownloadFile,
      openModal,
      onFileSelect,
    ],
  );

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  // Synchronizing selectedFile with the latest data from the cache for the modal
  useEffect(() => {
    if (modalOpen.link && selectedFile && files.length) {
      const updatedFile = files.find((f) => f.id === selectedFile.id);
      if (
        updatedFile &&
        (updatedFile.hasPublicLink !== selectedFile.hasPublicLink ||
          updatedFile.publicLinkUrl !== selectedFile.publicLinkUrl)
      ) {
        updateSelectedFile(updatedFile);
      }
    }
  }, [files, modalOpen.link, selectedFile, updateSelectedFile]);

  // Reset pagination when uploads complete (new files at top of page 1)
  useEffect(() => {
    if (!isUploadQueueCompleted) return;
    window.scrollTo({ top: 0, behavior: "smooth" });
    resetPagination();
  }, [isUploadQueueCompleted, resetPagination]);

  // ---------------------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------------------

  return (
    <div className="file-manager">
      <header className="file-manager__header">
        <FileManagerHeader
          isAdmin={isAdmin}
          userId={userId}
          searchTerm={searchTerm}
          onSearchChange={handleSearchChange}
        />
      </header>

      <FileManagerDropzone
        isVisible={
          !isAdmin &&
          !debouncedSearchTerm &&
          files.length === 0 &&
          !error &&
          !isLoading &&
          !isFetching
        }
      />

      <FileManagerContent
        hasNextPage={hasNextPage}
        isFetching={isFetching}
        loadMore={loadMore}
        fileListProps={preparedListData}
      />

      {/* File actions modals */}
      <DeleteFileModal
        isOpen={modalOpen.delete}
        file={selectedFile}
        onConfirm={handleDeleteConfirm}
        onClose={() => closeModal("delete")}
        isDeleting={isDeleting}
      />
      <RenameFileModal
        key={selectedFile?.id}
        isOpen={modalOpen.rename}
        onClose={() => closeModal("rename")}
        file={selectedFile}
        onSubmit={handleRenameSubmit}
        isSubmitting={isRenaming}
      />
      <EditCommentModal
        isOpen={modalOpen.comment}
        onClose={() => closeModal("comment")}
        file={selectedFile}
        onSubmit={handleCommentUpdate}
        isSubmitting={isUpdatingComment}
      />
      <PublicLinkModal
        isOpen={modalOpen.link}
        file={selectedFile}
        onGenerate={handleGeneratePublicLink}
        onCopy={handleCopyPublicLink}
        onClose={() => closeModal("link")}
        onDelete={handleDeletePublicLink}
        isGenerating={isGeneratingLink}
        isDeleting={isDeletingLink}
      />
      <ImageViewerModal
        isOpen={modalOpen.imageViewer}
        file={selectedImageFile}
        onClose={() => closeModal("imageViewer")}
      />
    </div>
  );
}
