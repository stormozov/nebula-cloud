import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ModalConfirm, type ModalConfirmProps } from "../ModalConfirm";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../../buttons", () => ({
  Button: vi.fn(({ children, onClick, disabled, variant }) => (
    <button
      type="button"
      data-testid={`mock-button-${variant}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  )),
}));

vi.mock("../../Icon", () => ({
  Icon: vi.fn(({ name }) => <span data-testid={`icon-${name}`} />),
}));

vi.mock("../../layouts", () => ({
  PageWrapper: vi.fn(({ children, className, justify }) => (
    <div
      data-testid="mock-page-wrapper"
      data-justify={justify}
      className={className}
    >
      {children}
    </div>
  )),
}));

vi.mock("../../Modal", () => ({
  Modal: vi.fn(
    ({
      children,
      isOpen,
      title,
      closeOnOverlayClick,
      closeOnEsc,
      onClose,
      className,
    }) => (
      <div
        data-testid="mock-modal"
        data-isopen={isOpen}
        data-title={title}
        data-close-on-overlay={closeOnOverlayClick}
        data-close-on-esc={closeOnEsc}
        data-classname={className}
      >
        <button
          type="button"
          data-testid="mock-modal-close"
          onClick={onClose}
        />
        <div>{title}</div>
        {children}
      </div>
    ),
  ),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("ModalConfirm", () => {
  const defaultProps: ModalConfirmProps = {
    isOpen: true,
    title: "Test Title",
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
    onClose: vi.fn(),
    children: "Test message content",
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderModalConfirm = (props: Partial<ModalConfirmProps> = {}) => {
    const finalProps = { ...defaultProps, ...props };
    return render(<ModalConfirm {...finalProps} />);
  };

  describe("when modal is rendered", () => {
    /**
     * @description Should render Modal with correct props and children content
     * @scenario Component mounts with default props and isOpen=true
     * @expected Modal receives isOpen=true, custom title, children content is displayed
     */
    it("should render modal with title and children content", () => {
      // Arrange & Act
      renderModalConfirm();

      // Assert
      const modal = screen.getByTestId("mock-modal");
      expect(modal).toBeInTheDocument();
      expect(modal).toHaveAttribute("data-isopen", "true");
      expect(modal).toHaveAttribute("data-title", "Test Title");
      expect(screen.getByText("Test message content")).toBeInTheDocument();
    });

    /**
     * @description Should use default title when title prop is not provided
     * @scenario Component renders without title prop
     * @expected Modal receives default title "Подтвердите действие"
     */
    it("should use default title when title is not provided", () => {
      // Arrange & Act
      renderModalConfirm({ title: undefined });

      // Assert
      const modal = screen.getByTestId("mock-modal");
      expect(modal).toHaveAttribute("data-title", "Подтвердите действие");
    });

    /**
     * @description Should render confirm and cancel buttons with icons
     * @scenario Component renders with default buttons
     * @expected Buttons with variants "primary" and "secondary" are present with icons
     */
    it("should render confirm and cancel buttons with icons", () => {
      // Arrange & Act
      renderModalConfirm();

      // Assert
      expect(screen.getByTestId("mock-button-primary")).toBeInTheDocument();
      expect(screen.getByTestId("mock-button-secondary")).toBeInTheDocument();
      expect(screen.getByTestId("icon-check")).toBeInTheDocument();
      expect(screen.getByTestId("icon-close")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("when user confirms action", () => {
    /**
     * @description Should call onConfirm and onClose when confirm button is clicked
     * @scenario Confirm button clicked, async handlers resolve
     * @expected onConfirm called once, onClose called once after completion
     */
    it("should call onConfirm and onClose on successful confirm", async () => {
      // Arrange
      const user = userEvent.setup();
      const onConfirm = vi.fn().mockResolvedValue(undefined);
      const onClose = vi.fn();
      renderModalConfirm({ onConfirm, onClose });

      // Act
      const confirmButton = screen.getByTestId("mock-button-primary");
      await user.click(confirmButton);

      // Assert
      expect(onConfirm).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should show loading state and prevent double clicks while confirming
     * @scenario Confirm button clicked multiple times before async resolves
     * @expected onConfirm called only once, button disabled during loading
     */
    it("should disable buttons and show loading text while confirm is processing", async () => {
      // Arrange
      const user = userEvent.setup();
      let resolveConfirm: () => void;
      const onConfirm = vi.fn().mockImplementation(
        () =>
          new Promise<void>((resolve) => {
            resolveConfirm = resolve;
          }),
      );
      const onClose = vi.fn();
      renderModalConfirm({ onConfirm, onClose });

      // Act
      const confirmButton = screen.getByTestId("mock-button-primary");
      await user.click(confirmButton);

      // Assert loading state
      expect(screen.getByTestId("mock-button-primary")).toBeDisabled();
      expect(screen.getByTestId("mock-button-secondary")).toBeDisabled();
      expect(screen.getByText("Загрузка...")).toBeInTheDocument();
      expect(onConfirm).toHaveBeenCalledTimes(1);
      expect(onClose).not.toHaveBeenCalled();

      // Try second click
      await user.click(confirmButton);
      expect(onConfirm).toHaveBeenCalledTimes(1); // still once

      // Act - resolve promise
      await act(async () => {
        resolveConfirm();
      });

      // Assert after resolve
      expect(onClose).toHaveBeenCalledTimes(1);
      expect(screen.getByTestId("mock-button-primary")).not.toBeDisabled();
    });

    /**
     * @description Should log error and NOT call onClose when onConfirm throws
     * @scenario Confirm button clicked, onConfirm rejects with error
     * @expected Error logged, onClose not called, loading state reset
     */
    it("should log error and not close modal when onConfirm fails", async () => {
      // Arrange
      const consoleErrorSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const user = userEvent.setup();
      const mockError = new Error("Confirm failed");
      const onConfirm = vi.fn().mockRejectedValue(mockError);
      const onClose = vi.fn();
      renderModalConfirm({ onConfirm, onClose });

      // Act
      const confirmButton = screen.getByTestId("mock-button-primary");
      await user.click(confirmButton);

      // Assert
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        "Confirm action failed:",
        mockError,
      );
      expect(onConfirm).toHaveBeenCalledTimes(1);
      expect(onClose).not.toHaveBeenCalled();
      expect(screen.getByTestId("mock-button-primary")).not.toBeDisabled();

      consoleErrorSpy.mockRestore();
    });
  });

  // ===========================================================================

  describe("when user cancels action", () => {
    /**
     * @description Should call onCancel and onClose when cancel button is clicked
     * @scenario Cancel button clicked, async handlers resolve
     * @expected onCancel called once, onClose called once
     */
    it("should call onCancel and onClose on successful cancel", async () => {
      // Arrange
      const user = userEvent.setup();
      const onCancel = vi.fn().mockResolvedValue(undefined);
      const onClose = vi.fn();
      renderModalConfirm({ onCancel, onClose });

      // Act
      const cancelButton = screen.getByTestId("mock-button-secondary");
      await user.click(cancelButton);

      // Assert
      expect(onCancel).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should log error and not close modal when onCancel throws
     * @scenario Cancel button clicked, onCancel rejects with error
     * @expected Error logged, onClose not called
     */
    it("should log error and not close modal when onCancel fails", async () => {
      // Arrange
      const consoleErrorSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const user = userEvent.setup();
      const mockError = new Error("Cancel failed");
      const onCancel = vi.fn().mockRejectedValue(mockError);
      const onClose = vi.fn();
      renderModalConfirm({ onCancel, onClose });

      // Act
      const cancelButton = screen.getByTestId("mock-button-secondary");
      await user.click(cancelButton);

      // Assert
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        "Cancel action failed:",
        mockError,
      );
      expect(onCancel).toHaveBeenCalledTimes(1);
      expect(onClose).not.toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  // ===========================================================================

  describe("when modal closes via overlay or ESC", () => {
    /**
     * @description Should pass closeOnOverlayClick and closeOnEsc props to Modal with loading block
     * @scenario Component renders with default closeOnOverlayClick=true and closeOnEsc=true, not loading
     * @expected Modal receives true for both props
     */
    it("should pass closeOnOverlayClick and closeOnEsc as true to Modal when not loading", () => {
      // Arrange & Act
      renderModalConfirm({ closeOnOverlayClick: true, closeOnEsc: true });

      // Assert
      const modal = screen.getByTestId("mock-modal");
      expect(modal).toHaveAttribute("data-close-on-overlay", "true");
      expect(modal).toHaveAttribute("data-close-on-esc", "true");
    });

    /**
     * @description Should disable overlay/ESC closing when isLoading is true
     * @scenario Confirm button clicked, loading starts, then Modal receives false for close props
     * @expected Modal receives closeOnOverlayClick=false and closeOnEsc=false during loading
     */
    it("should disable closeOnOverlayClick and closeOnEsc while loading", async () => {
      // Arrange
      const user = userEvent.setup();
      let resolveConfirm: () => void;
      const onConfirm = vi.fn().mockImplementation(
        () =>
          new Promise<void>((resolve) => {
            resolveConfirm = resolve;
          }),
      );
      renderModalConfirm({
        onConfirm,
        closeOnOverlayClick: true,
        closeOnEsc: true,
      });

      // Act
      const confirmButton = screen.getByTestId("mock-button-primary");
      await user.click(confirmButton);

      // Assert
      const modal = screen.getByTestId("mock-modal");
      expect(modal).toHaveAttribute("data-close-on-overlay", "false");
      expect(modal).toHaveAttribute("data-close-on-esc", "false");

      // Cleanup
      await act(async () => {
        resolveConfirm();
      });
    });

    /**
     * @description Should call handleCancel (which triggers onCancel + onClose) when Modal onClose is triggered
     * @scenario Modal's onClose is called (e.g., by pressing ESC or clicking overlay)
     * @expected onCancel and onClose are called, modal closes
     */
    it("should call onCancel and onClose when modal close is triggered via onClose prop", async () => {
      // Arrange
      const onCancel = vi.fn().mockResolvedValue(undefined);
      const onClose = vi.fn();
      renderModalConfirm({ onCancel, onClose });

      // Act
      const modalCloseButton = screen.getByTestId("mock-modal-close");
      await userEvent.click(modalCloseButton);

      // Assert
      expect(onCancel).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  // ===========================================================================

  describe("when children is not provided", () => {
    /**
     * @description Should not render content div when children is undefined
     * @scenario Component rendered without children prop
     * @expected No element with class "modal-confirm__content" is present
     */
    it("should not render content div when children is missing", () => {
      // Arrange & Act
      const { container } = renderModalConfirm({ children: undefined });

      // Assert
      expect(
        container.querySelector(".modal-confirm__content"),
      ).not.toBeInTheDocument();
    });
  });
});
