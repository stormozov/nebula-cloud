import { useMemo } from "react";

import type { IFile } from "@/entities/file";
import type { IDropdownMenuActionItem } from "@/shared/ui/DropdownMenu/types";
import { isImageFile } from "@/shared/utils";

import type { IFileHandlersProps } from "./types";

/**
 * Props for `useFileActions` hook.
 */
interface IUseFileActionsProps {
  file: IFile;
  handlers: IFileHandlersProps;
};

/**
 * Generates action items for a file to be used in `DropdownMenu`.
 *
 * Actions are conditionally included based on provided callbacks and file props
 */
export const useFileActions = ({
  file,
  handlers,
}: IUseFileActionsProps): IDropdownMenuActionItem<IFile>[] => {
  const {
    onView,
    onDownload,
    onPublicLink,
    onRename,
    onEditComment,
    onDelete,
  } = handlers;

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
