import classNames from "classnames";

import type { IFileIconProps } from "./types";
import { FILE_TYPE_ICONS, getFileType, getFileTypeRuLabel } from "./utils";

import "./FileIcon.scss";

/**
 * File icon component based on file extension.
 */
export function FileIcon({
  filename = "",
  size = 24,
  className = "",
  showTooltip = false,
}: IFileIconProps) {
  const fileType = getFileType(filename);
  const tooltipText = getFileTypeRuLabel(fileType);

  const iconClasses = classNames(
    "file-icon",
    `file-icon--${fileType}`,
    className,
  );

  // istanbul ignore next
  const Icon = FILE_TYPE_ICONS[fileType] || FILE_TYPE_ICONS.unknown;

  return (
    <Icon
      size={size}
      className={iconClasses}
      title={showTooltip ? tooltipText : undefined}
      aria-label={tooltipText}
    />
  );
}
