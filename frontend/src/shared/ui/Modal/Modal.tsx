import classNames from "classnames";
import { useCallback, useEffect, useRef } from "react";

import { Button } from "../buttons";
import type { IModalProps } from "./types";

import "./Modal.scss";

/**
 * Base modal component with animations and accessibility.
 *
 * Supports close on: button click, overlay click, ESC key.
 *
 * @example
 * <Modal isOpen={isOpen} title="Delete File" onClose={handleClose}>
 *   <p>Are you sure?</p>
 * </Modal>
 */
export function Modal({
  isOpen,
  className,
  ariaLabel,
  title,
  children,
  footer,
  focusTarget,
  closeOnOverlayClick = true,
  closeOnEsc = true,
  closeOnButton = true,
  onClose,
}: IModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

  const handleKeyDown = useCallback(
    (event: KeyboardEvent): void => {
      if (!closeOnEsc) return;
      if (event.key === "Escape") onClose();
    },
    [closeOnEsc, onClose],
  );

  const handleOverlayClick = (
    event: React.MouseEvent<HTMLDivElement>,
  ): void => {
    if (!closeOnOverlayClick) return;
    if (event.target === event.currentTarget) onClose();
  };

  const handleCloseButtonClick = (): void => {
    if (closeOnButton) onClose();
  };

  // ---------------------------------------------------------------------------
  // FOCUS TRAP
  // ---------------------------------------------------------------------------

  /**
   * Focus trap: focus first focusable element when modal opens.
   */
  useEffect(() => {
    if (isOpen) {
      // Store previous focus
      previousFocusRef.current = document.activeElement as HTMLElement;

      // Focus target first if provided, else first focusable
      let focusableElement: HTMLElement | null = null;
      if (focusTarget?.current) {
        focusableElement = focusTarget.current;
      } else {
        const queryResult = modalRef.current?.querySelector<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        focusableElement = queryResult || null;
      }
      focusableElement?.focus();

      // Add keyboard listener
      document.addEventListener("keydown", handleKeyDown);

      // Prevent body scroll
      document.body.style.overflow = "hidden";
    }

    return () => {
      // Cleanup
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "";

      // Restore previous focus or target
      previousFocusRef.current?.focus();
    };
  }, [isOpen, handleKeyDown, focusTarget]);

  // ---------------------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------------------

  // Don't render if closed
  if (!isOpen) return null;

  return (
    // biome-ignore lint/a11y/useKeyWithClickEvents: <dialog is used for accessibility>
    <div
      className="modal-overlay"
      onClick={handleOverlayClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      aria-label={ariaLabel || title}
    >
      <div
        ref={modalRef}
        className={classNames("modal", className, {
          "modal--open": isOpen,
        })}
      >
        {/* Header */}
        <header className="modal__header">
          <h2 id="modal-title" className="modal__title">
            {title}
          </h2>
          {closeOnButton && (
            <Button
              variant="ghost"
              className="modal__close-btn"
              onClick={handleCloseButtonClick}
              aria-label="Закрыть модальное окно"
              icon={{ name: "close" }}
            />
          )}
        </header>

        {/* Content */}
        <div className="modal__content">{children}</div>

        {/* Footer (optional) */}
        {footer && <div className="modal__footer">{footer}</div>}
      </div>
    </div>
  );
}
