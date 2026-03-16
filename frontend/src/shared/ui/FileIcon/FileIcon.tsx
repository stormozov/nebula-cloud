import classNames from "classnames";

import type { IFileIconProps } from "./types";
import { getFileIconSymbol, getFileType, getFileTypeRuLabel } from "./utils";

import "./FileIcon.scss";

/**
 * File icon component based on file extension.
 *
 * Displays appropriate icon and color for different file types.
 *
 * @param {IFileIconProps} props - Component props
 * @param {string} props.filename - File name or extension
 * @param {number} props.size - Icon size in pixels (default: 24)
 * @param {string} props.className - Additional CSS class
 * @param {boolean} props.showTooltip - Show tooltip with file type
 *
 * @example
 * <FileIcon filename="document.pdf" size={32} />
 * <FileIcon filename="image.png" showTooltip />
 */
export function FileIcon({
  filename,
  size = 24,
  className,
  showTooltip = false,
}: IFileIconProps) {
  const fileType = getFileType(filename);
  const iconClasses = classNames(
    "file-icon",
    `file-icon--${fileType}`,
    className,
  );

  const tooltipText = getFileTypeRuLabel(fileType);

  return (
    <div
      className={iconClasses}
      style={{ width: size, height: size }}
      role="img"
      title={showTooltip ? tooltipText : undefined}
      aria-label={tooltipText}
    >
      <span className="file-icon__symbol">{getFileIconSymbol(fileType)}</span>
    </div>
  );
}
