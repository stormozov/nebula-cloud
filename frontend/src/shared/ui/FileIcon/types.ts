/**
 * File type categories for icon selection.
 */
export type FileType =
  | "image"
  | "video"
  | "audio"
  | "document"
  | "archive"
  | "code"
  | "unknown";

/**
 * FileIcon component props.
 */
export interface IFileIconProps {
  /**
   * File name or extension to determine icon type.
   */
  filename: string;

  /**
   * Icon size in pixels.
   */
  size?: number;

  /**
   * Additional CSS class name.
   */
  className?: string;

  /**
   * Show tooltip with file type.
   */
  showTooltip?: boolean;
}
