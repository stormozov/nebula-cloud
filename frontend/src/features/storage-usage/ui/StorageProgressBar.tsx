import classNames from "classnames";

import {
  STORAGE_CRITICAL_THRESHOLD,
  STORAGE_WARNING_THRESHOLD,
} from "../lib/constants";
import type { IStorageProgressBarProps } from "../lib/types";

import "./StorageProgressBar.scss";

/**
 * A React component that visually represents storage usage as a progress bar
 * with optional labels and status indicators.
 */
export const StorageProgressBar = ({
  used,
  total,
  usedFormatted,
  totalFormatted,
  percent,
  showLabels = true,
  variant = "default",
  className,
}: IStorageProgressBarProps) => {
  const clampedPercent = Math.min(100, Math.max(0, percent));
  const isWarning = percent >= STORAGE_WARNING_THRESHOLD * 100;
  const isCritical = percent >= STORAGE_CRITICAL_THRESHOLD * 100;

  const busynessText = isCritical
    ? "Ваш диск заполнен"
    : isWarning
      ? "Ваш диск почти заполнен"
      : "Занятость диска";

  const progressBarClasses = classNames(
    "storage-progress-bar",
    `storage-progress-bar--${variant}`,
    {
      "storage-progress-bar--warning": isWarning && !isCritical,
      "storage-progress-bar--critical": isCritical,
    },
    className,
  );

  return (
    <div
      className={progressBarClasses}
      title={`Занято ${usedFormatted} из ${totalFormatted} (${clampedPercent}%)`}
    >
      {showLabels && (
        <div className="storage-progress-bar__labels">
          <span className="storage-progress-bar__used">{usedFormatted}</span>
          <span className="storage-progress-bar__total">{totalFormatted}</span>
        </div>
      )}

      <div
        className="storage-progress-bar__track"
        role="progressbar"
        aria-valuenow={used}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuetext={`${usedFormatted} из ${totalFormatted}`}
      >
        <div
          className="storage-progress-bar__fill"
          style={{ width: `${clampedPercent}%` }}
        />
      </div>

      {variant === "default" && showLabels && (
        <div className="storage-progress-bar__extra">
          <p className="storage-progress-bar__busyness">{busynessText}</p>
          <span className="storage-progress-bar__percent">
            {clampedPercent}%
          </span>
        </div>
      )}
    </div>
  );
};
