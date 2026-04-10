import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Props interface for the `useAnimatedClose` hook.
 */
export interface IUseAnimatedCloseProps {
  /** Callback to execute after animation completes (actual close) */
  onClose: () => void;
  /** Whether closing is blocked (e.g., during active upload) */
  isBlocked?: boolean;
  /** Animation duration in milliseconds */
  animationDuration?: number;
}

/**
 * Return type of the `useAnimatedClose` hook.
 */
export interface IUseAnimatedCloseReturn {
  /** Whether the component is in closing animation state */
  isClosing: boolean;
  /** Trigger animated close */
  handleCloseWithAnimation: () => void;
}

/**
 * Hook for animated closing of modals, panels, drawers, etc.
 *
 * Handles:
 * - Animated closing with configurable duration
 * - ESC key support (unless blocked)
 * - Prevents multiple close attempts
 * - Cleanup of timeouts
 */
export const useAnimatedClose = ({
  onClose,
  isBlocked = false,
  animationDuration = 300,
}: IUseAnimatedCloseProps): IUseAnimatedCloseReturn => {
  const [isClosing, setIsClosing] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>(null);

  const handleCloseWithAnimation = useCallback(() => {
    if (isClosing || isBlocked) return;
    setIsClosing(true);
    timeoutRef.current = setTimeout(() => {
      setIsClosing(false);
      onClose();
    }, animationDuration);
  }, [animationDuration, isBlocked, isClosing, onClose]);

  // ESC key listener
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

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  return { isClosing, handleCloseWithAnimation };
};
