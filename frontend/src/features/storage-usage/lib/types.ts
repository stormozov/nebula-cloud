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
  /** Visual style variant for the progress bar. */
  variant?: "default" | "bordered";
  /**
   * Optional flag to control the visibility of the label section showing
   * `usedFormatted` and `totalFormatted`.
   */
  showLabels?: boolean;
  /** Optional flag to enable compact mode */
  compact?: boolean;
  /** Optional CSS class name to be applied to the root element  */
  className?: string;
}
