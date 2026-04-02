import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Props for the `useModalClose` hook.
 */
interface UseModalCloseProps {
  /** Callback to close the modal */
  onClose: () => void;
  /** Whether the modal should be blocked from closing */
  isBlocked?: boolean;
  /** Duration of the closing animation in milliseconds */
  animationDuration?: number;
}

/**
 * Return value of the `useModalClose` hook.
 */
interface UseModalCloseReturns {
  /** Whether the modal is currently closing */
  isClosing: boolean;
  /** Function to close the modal with animation */
  handleCloseWithAnimation: () => void;
}

/**
 * React hook that manages the closing behavior of a modal with animation
 * support.
 *
 * Handles:
 * - Animated closing sequence with configurable duration
 * - ESC key press to close the modal (unless blocked)
 * - Prevention of multiple concurrent close attempts
 * - Cleanup of pending timeouts on unmount
 *
 * @example
 * const { isClosing, handleCloseWithAnimation } = useModalClose({
 *   onClose: () => setIsOpen(false),
 *   isBlocked: isFormDirty,
 *   animationDuration: 300
 * });
 */
export const useModalClose = ({
  onClose,
  isBlocked = false,
  animationDuration = 300,
}: UseModalCloseProps): UseModalCloseReturns => {
  const [isClosing, setIsClosing] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>(null);

  const handleCloseWithAnimation = useCallback(() => {
    if (isClosing || isBlocked) return;
    setIsClosing(true);
    timeoutRef.current = setTimeout(() => onClose(), animationDuration);
  }, [animationDuration, isBlocked, isClosing, onClose]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !isBlocked) {
        e.preventDefault();
        handleCloseWithAnimation();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleCloseWithAnimation, isBlocked]);

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  return { isClosing, handleCloseWithAnimation };
};
