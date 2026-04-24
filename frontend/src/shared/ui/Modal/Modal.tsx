import classNames from "classnames";
import { useRef } from "react";
import { createPortal } from "react-dom";

import { useBodyScrollLock, useFocusTrap } from "@/shared/hooks";

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

  useFocusTrap({
    active: isOpen,
    containerRef: modalRef,
    onEscape: closeOnEsc ? onClose : undefined,
    initialFocusRef: focusTarget,
  });

  useBodyScrollLock(isOpen);

  // ---------------------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------------------

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
  // RENDER
  // ---------------------------------------------------------------------------

  // Don't render if closed
  if (!isOpen) return null;

  const modalContent = (
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

  return typeof document !== "undefined"
    ? createPortal(modalContent, document.body)
    : modalContent;
}
