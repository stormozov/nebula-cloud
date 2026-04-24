import { useCallback, useMemo } from "react";

import type { IFile } from "@/entities/file";
import type { DropdownMenuItem } from "@/shared/ui";
import { isImageFile } from "@/shared/utils";

import type { IFileHandlersProps } from "./types";

/**
 * Props for `useFileActions` hook.
 */
interface IUseFileActionsProps {
  /** File to generate actions for */
  file: IFile;
  /** Handlers for file actions */
  handlers: IFileHandlersProps;
}

/**
 * Generates action items for a file to be used in `DropdownMenu`.
 *
 * Actions are conditionally included based on provided callbacks and file props
 */
export const useFileActions = ({
  file,
  handlers,
}: IUseFileActionsProps): DropdownMenuItem<IFile>[] => {
  const {
    onView,
    onDownload,
    onPublicLink,
    onRename,
    onEditComment,
    onDelete,
  } = handlers;

  const isViewable = onView && isImageFile(file);

  const addSeparator = useCallback((items: DropdownMenuItem<IFile>[]) => {
    if (items.length > 0) items.push({ type: "separator" });
  }, []);

  const actions = useMemo(() => {
    const items: DropdownMenuItem<IFile>[] = [];

    if (isViewable) {
      items.push({
        id: "view",
        label: "Просмотр",
        icon: "eye",
        onClick: onView,
      });
    }

    if (onDownload) {
      items.push({
        id: "download",
        label: "Скачать",
        icon: "download",
        onClick: onDownload,
      });
    }

    if (onPublicLink) {
      items.push({
        id: "publicLink",
        label: "Публичная ссылка",
        icon: "share",
        onClick: onPublicLink,
      });
    }

    if (onRename) {
      items.push({
        id: "rename",
        label: "Переименовать",
        icon: "pencil",
        onClick: onRename,
      });
    }

    if (onEditComment) {
      items.push({
        id: "editComment",
        label: "Комментарий",
        icon: "comment",
        onClick: onEditComment,
      });
    }

    addSeparator(items);

    if (onDelete) {
      items.push({
        id: "delete",
        label: "Удалить",
        icon: "trash",
        isDanger: true,
        onClick: onDelete,
      });
    }

    return items;
  }, [
    isViewable,
    onView,
    onDownload,
    onPublicLink,
    onRename,
    onEditComment,
    onDelete,
    addSeparator,
  ]);

  return actions;
};
