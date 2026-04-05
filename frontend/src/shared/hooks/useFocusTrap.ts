import { type RefObject, useEffect, useRef } from "react";

/**
 * Props for the `useFocusTrap` hook.
 */
interface UseFocusTrapProps {
  /** Is modal active */
  active: boolean;
  /** Ref to the container */
  containerRef: RefObject<HTMLElement | null>;
  /** Close modal on escape */
  onEscape?: () => void;
  /** Initial focus element */
  initialFocusRef?: RefObject<HTMLElement | null>;
}

/**
 * Custom React hook that traps focus within a specified container element.
 *
 * When active, this hook ensures that keyboard navigation (e.g., Tab/Shift+Tab)
 * stays confined within the container. It also handles the Escape key if
 * an `onEscape` callback is provided. Upon deactivation, focus is restored
 * to the element that was focused before the trap was enabled.
 *
 * @example
 * const containerRef = useRef<HTMLDivElement>(null);
 * const initialFocusRef = useRef<HTMLButtonElement>(null);
 *
 * useFocusTrap({
 *   active: isOpen,
 *   containerRef,
 *   onEscape: closeModal,
 *   initialFocusRef,
 * });
 */
export function useFocusTrap({
  active,
  containerRef,
  onEscape,
  initialFocusRef,
}: UseFocusTrapProps) {
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!active) return;

    previousFocusRef.current = document.activeElement as HTMLElement;

    const getFocusableElements = () => {
      if (!containerRef.current) return [];
      return Array.from(
        containerRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      );
    };

    const setFocusTarget = () => {
      if (initialFocusRef?.current) {
        initialFocusRef.current.focus();
        return;
      }
      const focusable = getFocusableElements();
      if (focusable.length) focusable[0].focus();
    };

    setFocusTarget();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && onEscape) {
        onEscape();
        return;
      }

      if (e.key !== "Tab") return;

      const focusable = getFocusableElements();
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement as HTMLElement;

      // If Shift+Tab is pressed and the focus is on the first element,
      // switch to the last one
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      }
      // If Tab is pressed and the focus is on the last element, switch
      // to the first one
      else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (
        previousFocusRef.current &&
        document.body.contains(previousFocusRef.current)
      ) {
        previousFocusRef.current.focus();
      }
    };
  }, [active, containerRef, initialFocusRef, onEscape]);
}
