import classNames from "classnames";

import fileListConfig from "@/shared/configs/file-list.json";
import { Button } from "@/shared/ui";

import type {
  ActionHandlers,
  IFileAction,
  IFileItemActionsProps,
} from "../lib/types";

import "./FileItemActions.scss";

/** File action buttons configuration */
const FILE_ACTIONS: IFileAction[] = fileListConfig.actions;

/**
 * A component that renders a set of action buttons for a file item.
 *
 * The visibility and availability of each action depend on provided props
 * and file properties (e.g., `hasPublicLink`). Clicking an action triggers
 * the corresponding callback with the associated file.
 *
 * All click events stop propagation to prevent interference with parent
 * handlers.
 *
 * @example
 * <FileItemActions
 *   file={myFile}
 *   isVisible={true}
 *   onView={handleView}
 *   onDownload={handleDownload}
 *   onDelete={handleDelete}
 * />
 */
export function FileItemActions({
  file,
  isVisible,
  disabled = false,
  onView,
  onDownload,
  onPublicLink,
  onRename,
  onEditComment,
  onDelete,
}: IFileItemActionsProps) {
  const actionHandlers: ActionHandlers = {
    view: onView
      ? (e: React.MouseEvent) => {
          e.stopPropagation();
          onView(file);
        }
      : undefined,
    download: onDownload
      ? (e: React.MouseEvent) => {
          e.stopPropagation();
          onDownload(file);
        }
      : undefined,
    publicLink: onPublicLink
      ? (e: React.MouseEvent) => {
          e.stopPropagation();
          onPublicLink(file);
        }
      : undefined,
    rename: onRename
      ? (e: React.MouseEvent) => {
          e.stopPropagation();
          onRename(file);
        }
      : undefined,
    editComment: onEditComment
      ? (e: React.MouseEvent) => {
          e.stopPropagation();
          onEditComment(file);
        }
      : undefined,
    delete: onDelete
      ? (e: React.MouseEvent) => {
          e.stopPropagation();
          onDelete(file);
        }
      : undefined,
  };

  return (
    <div
      className={classNames("file-item-actions", {
        "file-item-actions--visible": isVisible,
      })}
    >
      {FILE_ACTIONS.map((action) => {
        const handler = actionHandlers[action.id];
        const isDisabled =
          disabled ||
          (action.id === "publicLink" && !file.hasPublicLink && !onPublicLink);

        return (
          <Button
            key={action.id}
            variant="secondary"
            size="small"
            className={classNames("file-item-actions__btn", {
              "file-item-actions__btn--danger": action.isDanger,
            })}
            title={action.title}
            aria-label={action.ariaLabel}
            onClick={handler}
            disabled={isDisabled}
          >
            {action.icon}
          </Button>
        );
      })}
    </div>
  );
}
