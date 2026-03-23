import type { IFile } from "@/entities/file";

/**
 * Interface representing a single file action configuration.
 */
export interface IFileAction {
  /**
   * Unique identifier for the action.
   */
  id: string;

  /**
   * Title text shown on hover.
   */
  title: string;

  /**
   * Aria-label for accessibility.
   */
  ariaLabel: string;

  /**
   * SVG icon element to render inside the button.
   */
  icon: React.ReactNode;

  /**
   * Indicates if the action is destructive (e.g., delete).
   */
  isDanger?: boolean;
}

/**
 * Table column configuration.
 */
export interface ITableColumn {
  /**
   * Unique key for the column.
   */
  key: string;

  /**
   * Human-readable label for the column.
   */
  label: string;

  /**
   * CSS class to apply to the column header cell.
   */
  className?: string;
}

/**
 * Props interface for the FileItemActions component.
 */
export interface IFileItemActionsProps {
  /**
   * The file object for which actions are being displayed.
   */
  file: IFile;

  /**
   * Determines whether the actions menu is visible.
   */
  isVisible: boolean;

  /**
   * Disables all action buttons when true.
   * @default false
   */
  disabled?: boolean;

  /**
   * Handler function triggered when the 'View' action is clicked.
   */
  onView?: (file: IFile) => void;

  /**
   * Handler function triggered when the 'Download' action is clicked.
   */
  onDownload?: (file: IFile) => void;

  /**
   * Handler function triggered when the 'Public Link' action is clicked.
   */
  onPublicLink?: (file: IFile) => void;

  /**
   * Handler function triggered when the 'Rename' action is clicked.
   */
  onRename?: (file: IFile) => void;

  /**
   * Handler function triggered when the 'Edit Comment' action is clicked.
   */
  onEditComment?: (file: IFile) => void;

  /**
   * Handler function triggered when the 'Delete' action is clicked.
   */
  onDelete?: (file: IFile) => void;
}

/**
 * Props for FileListHeader component.
 */
export interface IFileListHeaderProps {
  /**
   * Array of table column configurations.
   */
  columns: ITableColumn[];
}

/**
 * Props interface for the FileListBody component.
 */
export interface IFileListBodyProps {
  /**
   * Array of file objects to be displayed in the list.
   */
  files: IFile[];

  /**
   * When true, disables interactions with all file items.
   * @default false
   */
  disabled?: boolean;

  /**
   * Optional callback triggered when a file is selected
   * (e.g., clicked or checked).
   */
  onSelect?: (file: IFile) => void;

  /**
   * Optional callback triggered when the 'View' action is invoked for
   * a file.
   */
  onView?: (file: IFile) => void;

  /**
   * Optional callback triggered when the 'Download' action is invoked for
   * a file.
   */
  onDownload?: (file: IFile) => void;

  /**
   * Optional callback triggered when the 'Public Link' action is invoked for
   * a file.
   */
  onPublicLink?: (file: IFile) => void;

  /**
   * Optional callback triggered when the 'Rename' action is invoked for a file.
   */
  onRename?: (file: IFile) => void;

  /**
   * Optional callback triggered when the 'Edit Comment' action is invoked for
   * a file.
   */
  onEditComment?: (file: IFile) => void;

  /**
   * Optional callback triggered when the 'Delete' action is invoked for a file.
   */
  onDelete?: (file: IFile) => void;
}

/**
 * Properties for the FileListItem component.
 */
export interface IFileListItemProps {
  /**
   * The file object to be displayed and interacted with.
   */
  file: IFile;

  /**
   * Optional flag to disable interactions with the file item.
   */
  disabled?: boolean;

  /**
   * Callback function triggered when the file is selected.
   */
  onSelect?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to view the file.
   */
  onView?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to download the file.
   */
  onDownload?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to generate or manage
   * a public link for the file.
   */
  onPublicLink?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to rename the file.
   */
  onRename?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to edit the comment
   * associated with the file.
   */
  onEditComment?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to delete the file.
   */
  onDelete?: (file: IFile) => void;
}

/**
 * Properties for the FileList component.
 */
export interface IFileListProps {
  /**
   * Array of file objects to be displayed in the list.
   */
  files: IFile[];

  /**
   * Optional flag indicating whether the file list is currently loading.
   */
  isLoading?: boolean;

  /**
   * Optional error message to display if an error occurred during file loading.
   * If `null` or undefined, no error is shown.
   */
  error?: string | null;

  /**
   * Optional message to display when the file list is empty.
   */
  emptyMessage?: string;

  /**
   * Callback function triggered when a file is selected.
   */
  onSelectFile?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to view a file.
   */
  onViewFile?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to download a file.
   */
  onDownloadFile?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to generate or manage
   * a public link for a file.
   */
  onPublicLinkFile?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to rename a file.
   */
  onRenameFile?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to edit the comment
   * of a file.
   */
  onEditCommentFile?: (file: IFile) => void;

  /**
   * Callback function triggered when the user requests to delete a file.
   */
  onDeleteFile?: (file: IFile) => void;
}

/**
 * Type defining the structure of an action handler map.
 */
export type ActionHandlers = Record<
  string,
  ((e: React.MouseEvent) => void) | undefined
>;
