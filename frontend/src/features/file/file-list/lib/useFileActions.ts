import { useMemo } from "react";

import type { IFile } from "@/entities/file";
import type { IDropdownMenuActionItem } from "@/shared/ui/DropdownMenu/types";
import { isImageFile } from "@/shared/utils";

/**
 * Properties for the `useFileActions` hook.
 */
export interface UseFileActionsProps {
  file: IFile;
  onView?: (file: IFile) => void;
  onDownload?: (file: IFile) => void;
  onPublicLink?: (file: IFile) => void;
  onRename?: (file: IFile) => void;
  onEditComment?: (file: IFile) => void;
  onDelete?: (file: IFile) => void;
}

/**
 * Generates action items for a file to be used in `DropdownMenu`.
 *
 * Actions are conditionally included based on provided callbacks and file props
 */
export const useFileActions = ({
  file,
  onView,
  onDownload,
  onPublicLink,
  onRename,
  onEditComment,
  onDelete,
}: UseFileActionsProps): IDropdownMenuActionItem<IFile>[] => {
  const isViewable = onView && isImageFile(file);

  const viewAction = useMemo<IDropdownMenuActionItem<IFile> | null>(
    () =>
      isViewable
        ? {
            id: "view",
            label: "Просмотр",
            icon: "eye",
            onClick: onView,
          }
        : null,
    [isViewable, onView],
  );

  const downloadAction = useMemo<IDropdownMenuActionItem<IFile> | null>(
    () =>
      onDownload
        ? {
            id: "download",
            label: "Скачать",
            icon: "download",
            onClick: onDownload,
          }
        : null,
    [onDownload],
  );

  const publicLinkAction = useMemo<IDropdownMenuActionItem<IFile> | null>(
    () =>
      onPublicLink
        ? {
            id: "publicLink",
            label: "Публичная ссылка",
            icon: "share",
            onClick: onPublicLink,
          }
        : null,
    [onPublicLink],
  );

  const renameAction = useMemo<IDropdownMenuActionItem<IFile> | null>(
    () =>
      onRename
        ? {
            id: "rename",
            label: "Переименовать",
            icon: "pencil",
            onClick: onRename,
          }
        : null,
    [onRename],
  );

  const editCommentAction = useMemo<IDropdownMenuActionItem<IFile> | null>(
    () =>
      onEditComment
        ? {
            id: "editComment",
            label: "Комментарий",
            icon: "comment",
            onClick: onEditComment,
          }
        : null,
    [onEditComment],
  );

  const deleteAction = useMemo<IDropdownMenuActionItem<IFile> | null>(
    () =>
      onDelete
        ? {
            id: "delete",
            label: "Удалить",
            icon: "trash",
            isDanger: true,
            onClick: onDelete,
          }
        : null,
    [onDelete],
  );

  return useMemo(
    () =>
      [
        viewAction,
        downloadAction,
        publicLinkAction,
        renameAction,
        editCommentAction,
        deleteAction,
      ].filter(
        (action): action is IDropdownMenuActionItem<IFile> => action !== null,
      ),
    [
      viewAction,
      downloadAction,
      publicLinkAction,
      renameAction,
      editCommentAction,
      deleteAction,
    ],
  );
};
