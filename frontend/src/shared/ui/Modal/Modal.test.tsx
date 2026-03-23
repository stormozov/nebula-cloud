import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Modal } from "./Modal";
import type { IModalProps } from "./types";

describe("Modal", () => {
  const defaultProps: IModalProps = {
    isOpen: true,
    title: "Test Modal",
    children: <div>Modal content</div>,
    onClose: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset body overflow style after each test
    document.body.style.overflow = "";
  });

  /**
   * @description Should not render when isOpen is false
   * @scenario Set isOpen={false}
   * @expected Modal content is not in the document
   */
  it("should not render when isOpen is false", () => {
    render(<Modal {...defaultProps} isOpen={false} />);

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByText("Test Modal")).not.toBeInTheDocument();
  });

  /**
   * @description Should render when isOpen is true
   * @scenario Set isOpen={true}
   * @expected Modal is visible with title and children
   */
  it("should render when isOpen is true", () => {
    render(<Modal {...defaultProps} isOpen={true} />);

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Test Modal")).toBeInTheDocument();
    expect(screen.getByText("Modal content")).toBeInTheDocument();
  });

  /**
   * @description Should display title correctly
   * @scenario Pass title prop
   * @expected Title appears in header
   */
  it("should display title correctly", () => {
    const title = "Custom Title";
    render(<Modal {...defaultProps} title={title} />);

    expect(screen.getByText(title)).toBeInTheDocument();
  });

  /**
   * @description Should render children content
   * @scenario Pass arbitrary children
   * @expected Children elements are rendered
   */
  it("should render children content", () => {
    render(
      <Modal {...defaultProps}>
        <p>Custom child</p>
        <button type="button">Action</button>
      </Modal>,
    );

    expect(screen.getByText("Custom child")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Action" })).toBeInTheDocument();
  });

  /**
   * @description Should render footer when provided
   * @scenario Pass footer prop
   * @expected Footer content is displayed
   */
  it("should render footer when provided", () => {
    render(
      <Modal
        {...defaultProps}
        footer={<button type="button">Submit</button>}
      />,
    );

    expect(screen.getByRole("button", { name: "Submit" })).toBeInTheDocument();
  });

  /**
   * @description Should not render footer when not provided
   * @scenario Omit footer prop
   * @expected No footer element
   */
  it("should not render footer when not provided", () => {
    render(<Modal {...defaultProps} />);

    const footer = document.querySelector(".modal__footer");
    expect(footer).not.toBeInTheDocument();
  });

  /**
   * @description Should call onClose when close button is clicked
   * @scenario Click close button with closeOnButton true (default)
   * @expected onClose called once
   */
  it("should call onClose when close button is clicked", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<Modal {...defaultProps} onClose={onClose} />);

    const closeButton = screen.getByRole("button", { name: /закрыть/i });
    await user.click(closeButton);

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  /**
   * @description Should not render close button when closeOnButton is false
   * @scenario Set closeOnButton={false}
   * @expected Close button absent
   */
  it("should not render close button when closeOnButton is false", () => {
    render(<Modal {...defaultProps} closeOnButton={false} />);

    const closeButton = screen.queryByRole("button", { name: /закрыть/i });
    expect(closeButton).not.toBeInTheDocument();
  });

  /**
   * @description Should not call onClose when overlay is clicked if closeOnOverlayClick is false
   * @scenario Set closeOnOverlayClick={false} and click overlay
   * @expected onClose not called
   */
  it("should not call onClose when overlay is clicked if closeOnOverlayClick is false", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <Modal {...defaultProps} onClose={onClose} closeOnOverlayClick={false} />,
    );

    const overlay = screen.getByRole("dialog").parentElement;
    if (overlay) await user.click(overlay);

    expect(onClose).not.toHaveBeenCalled();
  });

  /**
   * @description Should call onClose when Escape key is pressed
   * @scenario Press Escape with closeOnEsc true (default)
   * @expected onClose called once
   */
  it("should call onClose when Escape key is pressed", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<Modal {...defaultProps} onClose={onClose} />);

    await user.keyboard("{Escape}");

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  /**
   * @description Should not call onClose when Escape key is pressed if closeOnEsc is false
   * @scenario Set closeOnEsc={false} and press Escape
   * @expected onClose not called
   */
  it("should not call onClose when Escape key is pressed if closeOnEsc is false", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<Modal {...defaultProps} onClose={onClose} closeOnEsc={false} />);

    await user.keyboard("{Escape}");

    expect(onClose).not.toHaveBeenCalled();
  });

  /**
   * @description Should focus on focusTarget when modal opens
   * @scenario Provide focusTarget ref pointing to an input
   * @expected Input receives focus after modal opens
   */
  it("should focus on focusTarget when modal opens", async () => {
    const focusRef = React.createRef<HTMLInputElement>();
    const TestComponent = () => {
      const [isOpen, setIsOpen] = React.useState(true);
      return (
        <Modal
            isOpen={isOpen}
            title="Modal"
            onClose={() => setIsOpen(false)}
            focusTarget={focusRef as React.RefObject<HTMLElement>}
          >
            <input ref={focusRef} type="text" />
          </Modal>
      );
    };

    render(<TestComponent />);
    const input = screen.getByRole("textbox");
    await waitFor(() => {
      expect(document.activeElement).toBe(input);
    });
  });

  /**
   * @description Should focus on first focusable element when focusTarget not provided
   * @scenario Open modal with no focusTarget, but there is a button inside
   * @expected The first focusable element (close button) receives focus
   */
  it("should focus on first focusable element when focusTarget not provided", async () => {
    const TestComponent = () => {
      const [isOpen, setIsOpen] = React.useState(true);
      return (
        <Modal isOpen={isOpen} title="Modal" onClose={() => setIsOpen(false)}>
          <button type="button">Inner button</button>
        </Modal>
      );
    };

    render(<TestComponent />);
    // The close button is first in the modal header, then inner button
    const closeButton = screen.getByRole("button", { name: /закрыть/i });
    await waitFor(() => {
      expect(document.activeElement).toBe(closeButton);
    });
  });

  /**
   * @description Should restore focus to previously focused element when modal closes
   * @scenario Open modal from a button, then close it
   * @expected Focus returns to the original button
   */
  it("should restore focus to previously focused element when modal closes", async () => {
    const user = userEvent.setup();
    const TestComponent = () => {
      const [isOpen, setIsOpen] = React.useState(false);
      return (
        <>
          <button
            type="button"
            data-testid="trigger"
            onClick={() => setIsOpen(true)}
          >
            Open modal
          </button>
          <Modal isOpen={isOpen} title="Modal" onClose={() => setIsOpen(false)}>
            <button type="button">Close</button>
          </Modal>
        </>
      );
    };

    render(<TestComponent />);
    const trigger = screen.getByTestId("trigger");
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    // Open modal
    await user.click(trigger);
    const closeButton = screen.getByRole("button", { name: /закрыть/i });
    await waitFor(() => {
      expect(document.activeElement).toBe(closeButton);
    });

    // Close modal
    await user.click(closeButton);
    await waitFor(() => {
      expect(document.activeElement).toBe(trigger);
    });
  });

  /**
   * @description Should block body scroll when modal opens and restore on close
   * @scenario Open modal, check overflow, then close and check overflow restored
   * @expected body.style.overflow becomes "hidden" on open, "" on close
   */
  it("should block body scroll when modal opens and restore on close", async () => {
    const user = userEvent.setup();
    const TestComponent = () => {
      const [isOpen, setIsOpen] = React.useState(true);
      return (
        <Modal
          isOpen={isOpen}
          title="Test Modal"
          onClose={() => setIsOpen(false)}
        >
          <div>Content</div>
        </Modal>
      );
    };

    const { rerender } = render(<TestComponent />);
    expect(document.body.style.overflow).toBe("hidden");

    // Close modal by clicking close button
    const closeButton = screen.getByRole("button", { name: /закрыть/i });
    await user.click(closeButton);

    // Wait for rerender with isOpen=false (the parent will update)
    rerender(<TestComponent />);
    await waitFor(() => {
      expect(document.body.style.overflow).toBe("");
    });
  });

  /**
   * @description Should remove scroll lock when component unmounts while open
   * @scenario Mount modal, then unmount without closing
   * @expected body overflow restored
   */
  it("should remove scroll lock when component unmounts while open", () => {
    const { unmount } = render(<Modal {...defaultProps} isOpen={true} />);
    expect(document.body.style.overflow).toBe("hidden");

    unmount();
    expect(document.body.style.overflow).toBe("");
  });

  /**
   * @description Should have correct ARIA attributes for accessibility
   * @scenario Render modal with title and optional ariaLabel
   * @expected role="dialog", aria-modal="true", aria-labelledby, and aria-label (if provided)
   */
  it("should have correct ARIA attributes for accessibility", () => {
    render(<Modal {...defaultProps} ariaLabel="Custom label" />);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-labelledby", "modal-title");
    expect(dialog).toHaveAttribute("aria-label", "Custom label");
  });

  /**
   * @description Should use title as fallback for aria-label when not provided
   * @scenario Omit ariaLabel, pass title
   * @expected aria-label equals title
   */
  it("should use title as fallback for aria-label when not provided", () => {
    render(<Modal {...defaultProps} ariaLabel={undefined} />);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-label", "Test Modal");
  });

  /**
   * @description Should apply custom className to modal element
   * @scenario Pass className="custom-modal"
   * @expected Modal div has "custom-modal" class
   */
  it("should apply custom className to modal element", () => {
    render(<Modal {...defaultProps} className="custom-modal" />);
    const modalDiv = document.querySelector(".modal");
    expect(modalDiv).toHaveClass("custom-modal");
  });

  /**
   * @description Should have modal--open class when isOpen is true
   * @scenario isOpen={true}
   * @expected Modal element has class modal--open
   */
  it("should have modal--open class when isOpen is true", () => {
    render(<Modal {...defaultProps} isOpen={true} />);
    const modalDiv = document.querySelector(".modal");
    expect(modalDiv).toHaveClass("modal--open");
  });

  /**
   * @description Should not have modal--open class when isOpen is false (but modal not rendered)
   * @scenario isOpen={false}
   * @expected No modal rendered, so class doesn't exist
   */
  it("should not have modal--open class when isOpen is false", () => {
    render(<Modal {...defaultProps} isOpen={false} />);
    const modalDiv = document.querySelector(".modal");
    expect(modalDiv).not.toBeInTheDocument();
  });
});
