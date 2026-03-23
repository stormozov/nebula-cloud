import type { ReactNode } from "react";

/**
 * Modal component props.
 */
export interface IModalProps {
  /** Modal content (children). */
  children: ReactNode;
  /** Whether modal is visible. */
  isOpen: boolean;
  /** Additional CSS class name. */
  className?: string;
  /** ARIA label for accessibility. */
  ariaLabel?: string;
  /** Modal title (displayed in header). */
  title: string;
  /** Footer content (optional, e.g., action buttons). */
  footer?: ReactNode;
  /** Specific element to focus when modal opens (e.g., input ref). */
  focusTarget?: React.RefObject<HTMLElement>;
  /** Disable close on overlay click. */
  closeOnOverlayClick?: boolean;
  /** Disable close on ESC key. */
  closeOnEsc?: boolean;
  /** Disable close on button click. */
  closeOnButton?: boolean;
  /** Callback when modal should be closed. */
  onClose: () => void;
}


/**
 * Modal form props (for modals with forms).
 */
export interface IModalFormProps<T = unknown> {
  /** Whether modal is visible. */
  isOpen: boolean;
  /** Initial form data (optional). */
  initialData?: T;
  /** Whether form is submitting (shows loading state). */
  isSubmitting?: boolean;
  /** Form error message (optional). */
  error?: string | null;
  /** Callback when modal should be closed. */
  onClose: () => void;
  /** Callback when form is submitted successfully. */
  onSubmit: (data: T) => void | Promise<void>;
}
