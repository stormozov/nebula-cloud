import type { IFile } from "@/entities/file";
import type { IListStates, IListStatesRenders } from "@/shared/ui";

/**
 * Interface representing a single file action configuration.
 */
export interface IFileAction {
  /** Unique identifier for the action. */
  id: string;
  /** Title text shown on hover. */
  title: string;
  /** Aria-label for accessibility. */
  ariaLabel: string;
  /** SVG icon element to render inside the button. */
  icon: string;
  /** Indicates if the action is destructive (e.g., delete). */
  isDanger?: boolean;
}

/**
 * Table column configuration.
 */
export interface ITableColumn {
  /** Unique key for the column. */
  key: string;
  /** Human-readable label for the column. */
  label: string;
  /** CSS class to apply to the column header cell. */
  className?: string;
}

/**
 * Properties for the `useFileActions` hook.
 */
export interface IFileHandlersProps {
  /** Callback function triggered when the "View" action is triggered. */
  onView?: (file: IFile) => void;
  /** Callback function triggered when the "Download" action is triggered. */
  onDownload?: (file: IFile) => void;
  /** Callback function triggered when the "Public Link" action is triggered. */
  onPublicLink?: (file: IFile) => void;
  /** Callback function triggered when the "Rename" action is triggered. */
  onRename?: (file: IFile) => void;
  /** Callback function triggered when the "Edit Comment" action is triggered. */
  onEditComment?: (file: IFile) => void;
  /** Callback function triggered when the "Delete" action is triggered. */
  onDelete?: (file: IFile) => void;
}

/**
 * Properties for the FileList component.
 */
export interface IFileListProps {
  /** Array of file objects to be displayed in the list. */
  files: IFile[];
  /** Properties for the loading, error, and empty states. */
  states?: IListStates;
  /** Array of action configurations for the file items. */
  handlers: IFileHandlersProps;
  /** Custom rendering functions for the loading, error, and empty states. */
  renders?: IListStatesRenders;
  /** Array of table column configurations for header row. */
  headers?: ITableColumn[];
  /** Callback function triggered when a file is selected. */
  onSelectFile?: (file: IFile) => void;
}

/**
 * Props for FileListHeader component.
 */
export interface IFileListHeaderProps {
  /** Array of table column configurations. */
  columns: ITableColumn[];
}

/**
 * Props interface for the FileListBody component.
 */
export interface IFileListBodyProps {
  /** Array of file objects to be displayed in the list. */
  files: IFile[];
  /** When true, disables interactions with all file items. */
  disabled?: boolean;
  /** Array of action configurations for the file items. */
  handlers?: IFileHandlersProps;
  /** Optional callback triggered when a file is selected. */
  onSelect?: (file: IFile) => void;
}

/**
 * Properties for the FileListItem component.
 */
export interface IFileListItemProps {
  /** The file object to be displayed and interacted with. */
  file: IFile;
  /** Optional flag to disable interactions with the file item. */
  disabled?: boolean;
  /** Array of action configurations for the file item. */
  handlers?: IFileHandlersProps;
  /** Callback function triggered when the file item is selected. */
  onSelect?: (file: IFile) => void;
}
