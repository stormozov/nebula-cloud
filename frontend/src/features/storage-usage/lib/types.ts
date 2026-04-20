/**
 * Props interface for the `StorageProgressBar` component.
 */
export interface IStorageProgressBarProps {
  /** The amount of storage currently used, in bytes. */
  used: number;
  /** The total storage limit available, in bytes. */
  total: number;
  /** Formatted string representation of the used storage (e.g., "2.5 ГБ"). */
  usedFormatted: string;
  /** Formatted string representation of the total storage limit. */
  totalFormatted: string;
  /** The usage percentage as a numeric value between 0 and 100+. */
  percent: number;
  /**
   * Optional flag to control the visibility of the label section showing
   * `usedFormatted` and `totalFormatted`.
   */
  showLabels?: boolean;
  /**
   * Visual style variant for the progress bar.
   * - `"default"`: Shows labels, progress track, and additional info
   * (status text and percentage).
   * - `"compact"`: Minimalist style, typically hiding extra text and focusing
   * on the bar itself.
   */
  variant?: "default" | "compact";
  /** Optional CSS class name to be applied to the root element  */
  className?: string;
}
