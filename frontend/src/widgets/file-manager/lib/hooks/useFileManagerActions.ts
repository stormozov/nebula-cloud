import { useCallback } from "react";
import { toast } from "react-toastify";

import { useAppDispatch } from "@/app/store/hooks";
import type { IFile, IFileRename } from "@/entities/file";
import {
  downloadFileFromApi,
  useDeleteFileMutation,
  useDeletePublicLinkMutation,
  useGeneratePublicLinkMutation,
  useRenameFileMutation,
  useUpdateCommentMutation,
} from "@/entities/file";
import { userApi } from "@/entities/user";
import { camelToSnake } from "@/shared/utils";

import type { ModalType } from "./useFileManagerModals";

/**
 * Interface for the parameters passed to the `useFileManagerActions` hook.
 */
interface UseFileManagerActionsParams {
  /** The currently selected file, or null if no file is selected. */
  selectedFile: IFile | null;
  /**
   * Function to close the modal of a specific type.
   *
   * @param type - The type of modal to close.
   */
  closeModal: (type: ModalType) => void;
  /** Function to reset the pagination state. */
  resetPagination: () => void;
}

/**
 * Interface for the return values of the `useFileManagerActions` hook.
 */
interface IUseFileManagerActionsReturns {
  /** Boolean indicating whether a file is currently being deleted. */
  isDeleting: boolean;
  /** Boolean indicating whether a file is currently being renamed. */
  isRenaming: boolean;
  /** Boolean indicating whether a file comment is currently being updated. */
  isUpdatingComment: boolean;
  /** Boolean indicating whether a public link is currently being generated. */
  isGeneratingLink: boolean;
  /** Boolean indicating whether a public link is currently being deleted. */
  isDeletingLink: boolean;
  /** Callback to confirm the deletion of a file. */
  handleDeleteConfirm: () => Promise<void>;
  /** Callback to rename a file. */
  handleRenameSubmit: (newName: string) => Promise<void>;
  /** Callback to update the comment of a file. */
  handleCommentUpdate: (newComment: string) => Promise<void>;
  /** Callback to generate a public link for a file. */
  handleGeneratePublicLink: () => Promise<void>;
  /** Callback to delete a public link for a file. */
  handleDeletePublicLink: () => Promise<void>;
  /** Callback to copy the public link of a file. */
  handleCopyPublicLink: (url: string) => Promise<void>;
  /** Callback to download a file. */
  handleDownloadFile: (file: IFile) => Promise<void>;
}

/**
 * Custom hook for managing file operations in a file manager.
 */
export const useFileManagerActions = ({
  selectedFile,
  closeModal,
  resetPagination,
}: UseFileManagerActionsParams): IUseFileManagerActionsReturns => {
  const dispatch = useAppDispatch();

  const [deleteFile, { isLoading: isDeleting }] = useDeleteFileMutation();
  const [renameFile, { isLoading: isRenaming }] = useRenameFileMutation();
  const [updateComment, { isLoading: isUpdatingComment }] =
    useUpdateCommentMutation();
  const [generatePublicLink, { isLoading: isGeneratingLink }] =
    useGeneratePublicLinkMutation();
  const [deletePublicLink, { isLoading: isDeletingLink }] =
    useDeletePublicLinkMutation();

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  const handleDeleteConfirm = useCallback(async (): Promise<void> => {
    if (!selectedFile) return;
    try {
      resetPagination();
      await deleteFile(selectedFile.id).unwrap();
      closeModal("delete");
      dispatch(userApi.util.invalidateTags(["UserStorage"]));
      toast.success("Файл успешно удален");
    } catch {
      toast.error("Не удалось удалить файл");
    }
  }, [selectedFile, deleteFile, closeModal, resetPagination, dispatch]);

  const handleRenameSubmit = useCallback(
    async (newName: string): Promise<void> => {
      if (!selectedFile) return;
      try {
        await renameFile({
          id: selectedFile.id,
          data: camelToSnake({ original_name: newName }) as IFileRename,
        }).unwrap();
        closeModal("rename");
        toast.success("Файл успешно переименован");
      } catch {
        toast.error("Не удалось переименовать файл");
      }
    },
    [selectedFile, renameFile, closeModal],
  );

  const handleCommentUpdate = useCallback(
    async (newComment: string): Promise<void> => {
      if (!selectedFile) return;
      try {
        await updateComment({
          id: selectedFile.id,
          data: { comment: newComment },
        }).unwrap();
        closeModal("comment");
        toast.success("Комментарий успешно обновлен");
      } catch {
        toast.error("Не удалось обновить комментарии");
      }
    },
    [selectedFile, updateComment, closeModal],
  );

  const handleDownloadFile = useCallback(async (file: IFile): Promise<void> => {
    try {
      await downloadFileFromApi(file.id, file.originalName);
      toast.info("Началось скачивание файла");
    } catch {
      toast.error("Не удалось скачать файл");
    }
  }, []);

  const handleGeneratePublicLink = useCallback(async (): Promise<void> => {
    if (!selectedFile) return;
    try {
      await generatePublicLink(selectedFile.id).unwrap();
    } catch {
      toast.error("Не удалось сгенерировать ссылку");
    }
  }, [selectedFile, generatePublicLink]);

  const handleDeletePublicLink = useCallback(async (): Promise<void> => {
    if (!selectedFile) return;
    try {
      await deletePublicLink(selectedFile.id).unwrap();
      closeModal("link");
      toast.success("Публичная ссылка успешно удалена");
    } catch {
      toast.error("Не удалось удалить публичную ссылку");
    }
  }, [selectedFile, deletePublicLink, closeModal]);

  const handleCopyPublicLink = useCallback(
    async (url: string): Promise<void> => {
      try {
        await navigator.clipboard.writeText(url);
        toast.success("Ссылка скопирована");
      } catch {
        toast.error("Не удалось скопировать ссылку");
      }
    },
    [],
  );

  // ---------------------------------------------------------------------------
  // RETURNS
  // ---------------------------------------------------------------------------

  return {
    isDeleting,
    isRenaming,
    isUpdatingComment,
    isGeneratingLink,
    isDeletingLink,
    handleDeleteConfirm,
    handleRenameSubmit,
    handleCommentUpdate,
    handleGeneratePublicLink,
    handleDeletePublicLink,
    handleCopyPublicLink,
    handleDownloadFile,
  };
};
