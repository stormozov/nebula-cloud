/**
 * Props for ControlledTextarea component.
 */
export interface IControlledTextareaProps {
  /**
   * Textarea value (controlled).
   */
  value: string;
  /**
   * Change callback with new value.
   */
  onChange: (value: string) => void;
  /**
   * Blur callback (optional).
   */
  onBlur?: () => void;
  /**
   * Error message to display (optional).
   */
  error?: string;
  /**
   * Textarea label (optional).
   */
  label?: string;
  /**
   * Placeholder text (optional).
   */
  placeholder?: string;
  /**
   * Disable textarea (optional).
   */
  disabled?: boolean;
  /**
   * Mark as required (optional).
   */
  required?: boolean;
  /**
   * Additional CSS class (optional).
   */
  className?: string;
  /**
   * Number of visible rows (optional).
   */
  rows?: number;
  /**
   * Maximum length of text (optional).
   */
  maxLength?: number;
}
