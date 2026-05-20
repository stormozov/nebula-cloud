import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { IFile } from "@/entities/file";

import { EditCommentModal } from "./EditCommentModal";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/shared/ui/Modal", () => ({
  Modal: ({
    children,
    isOpen,
    onClose,
    title,
    footer,
  }: {
    children: React.ReactNode;
    isOpen: boolean;
    onClose: () => void;
    title: string;
    footer: React.ReactNode;
  }) =>
    isOpen ? (
      <div data-testid="modal" data-title={title}>
        <button
          type="button"
          data-testid="modal-overlay-close"
          onClick={onClose}
        />
        <div>{children}</div>
        <div data-testid="modal-footer">{footer}</div>
      </div>
    ) : null,
}));

vi.mock("@/shared/ui", () => ({
  ControlledTextarea: vi
    .fn()
    .mockImplementation(
      ({
        value,
        onChange,
        error,
        disabled,
        maxLength,
        ref,
        ...props
      }: {
        value: string;
        onChange: (val: string) => void;
        error?: string;
        disabled?: boolean;
        maxLength?: number;
        ref?: React.RefObject<HTMLTextAreaElement>;
        [key: string]: unknown;
      }) => (
        <div>
          <textarea
            data-testid="textarea"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            disabled={disabled}
            maxLength={maxLength}
            ref={ref}
            {...props}
          />
          {error && <div data-testid="textarea-error">{error}</div>}
        </div>
      ),
    ),
  Button: vi
    .fn()
    .mockImplementation(
      ({
        children,
        onClick,
        disabled,
        loading,
        variant,
      }: {
        children: React.ReactNode;
        onClick: () => void;
        disabled?: boolean;
        loading?: boolean;
        variant: string;
      }) => (
        <button
          type="button"
          data-testid={`button-${variant}`}
          onClick={onClick}
          disabled={disabled || loading}
          data-loading={loading}
        >
          {children}
        </button>
      ),
    ),
}));

const mockRequestAnimationFrame = vi
  .spyOn(window, "requestAnimationFrame")
  .mockImplementation((cb) => {
    cb(0);
    return 0;
  });

// =============================================================================
// TESTS
// =============================================================================

describe("EditCommentModal", () => {
  const mockFile: IFile = {
    id: 1,
    originalName: "test.pdf",
    comment: "Initial comment",
  } as IFile;

  const defaultProps = {
    isOpen: true,
    file: mockFile,
    onClose: vi.fn(),
    onSubmit: vi.fn(),
    isSubmitting: false,
    error: null,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when modal opens with a file", () => {
    /**
     * @description Should sync comment state with file.comment and focus/select textarea
     * @scenario Modal is opened with a non-null file having existing comment
     * @expected Textarea value equals file.comment; requestAnimationFrame called
     */
    it("should initialize textarea with file comment and focus it", () => {
      render(<EditCommentModal {...defaultProps} />);
      const textarea = screen.getByTestId("textarea") as HTMLTextAreaElement;
      expect(textarea.value).toBe(mockFile.comment);
      expect(mockRequestAnimationFrame).toHaveBeenCalled();
    });

    /**
     * @description Should reset validation error and sync comment when file changes
     * @scenario User had validation error, then modal closes and reopens with new file
     * @expected Validation error is cleared and comment resets to new file's comment
     */
    it("should reset validation error and sync comment when file changes", () => {
      const { rerender } = render(<EditCommentModal {...defaultProps} />);
      const newFile: IFile = { ...mockFile, comment: "Updated comment" };
      rerender(<EditCommentModal {...defaultProps} file={newFile} />);
      const textarea = screen.getByTestId("textarea") as HTMLTextAreaElement;
      expect(textarea.value).toBe("Updated comment");
      expect(screen.queryByTestId("textarea-error")).not.toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("validation", () => {
    /**
     * @description Should display error when comment exceeds 500 characters
     * @scenario Programmatically set comment length > 500 (bypassing maxLength) and submit
     * @expected Validation error message appears and onSubmit is not called
     */
    it("should show error when comment exceeds 500 characters", async () => {
      const user = userEvent.setup();
      render(<EditCommentModal {...defaultProps} />);
      const textarea = screen.getByTestId("textarea");
      const longText = "a".repeat(501);

      fireEvent.change(textarea, { target: { value: longText } });
      await user.click(screen.getByTestId("button-primary"));

      expect(await screen.findByTestId("textarea-error")).toHaveTextContent(
        "Комментарий слишком длинный (максимум 500 символов)",
      );
      expect(defaultProps.onSubmit).not.toHaveBeenCalled();
    });

    /**
     * @description Should show error when comment is unchanged compared to original file comment
     * @scenario User does not modify the comment and clicks submit
     * @expected Validation error about unchanged comment appears
     */
    it("should show error when comment unchanged", async () => {
      const user = userEvent.setup();
      render(<EditCommentModal {...defaultProps} />);
      const textarea = screen.getByTestId("textarea") as HTMLTextAreaElement;
      // Ensure textarea still contains the original comment
      expect(textarea.value).toBe(mockFile.comment);

      await user.click(screen.getByTestId("button-primary"));

      expect(await screen.findByTestId("textarea-error")).toHaveTextContent(
        "Обновляемый комментарий не должно совпадать с исходным",
      );
      expect(defaultProps.onSubmit).not.toHaveBeenCalled();
    });

    /**
     * @description Should clear validation error when user starts typing after error
     * @scenario Validation error shown (e.g., too long), then user changes input
     * @expected Error disappears
     */
    it("should clear validation error on input change", async () => {
      const user = userEvent.setup();
      render(<EditCommentModal {...defaultProps} />);
      const textarea = screen.getByTestId("textarea");
      const longText = "a".repeat(501);

      fireEvent.change(textarea, { target: { value: longText } });
      await user.click(screen.getByTestId("button-primary"));
      expect(await screen.findByTestId("textarea-error")).toBeInTheDocument();

      fireEvent.change(textarea, { target: { value: "valid short text" } });

      await waitFor(() => {
        expect(screen.queryByTestId("textarea-error")).not.toBeInTheDocument();
      });
    });
  });

  // ===========================================================================

  describe("submission", () => {
    /**
     * @description Should call onSubmit with trimmed comment when valid
     * @scenario User enters a new valid comment and clicks Save
     * @expected onSubmit called with trimmed comment, no validation error
     */
    it("should call onSubmit with trimmed comment when valid", async () => {
      const user = userEvent.setup();
      const onSubmitMock = vi.fn().mockResolvedValue(undefined);
      render(<EditCommentModal {...defaultProps} onSubmit={onSubmitMock} />);
      const textarea = screen.getByTestId("textarea");
      const newComment = "  New valid comment  ";

      fireEvent.change(textarea, { target: { value: newComment } });
      await user.click(screen.getByTestId("button-primary"));

      expect(onSubmitMock).toHaveBeenCalledTimes(1);
      expect(onSubmitMock).toHaveBeenCalledWith("New valid comment");
      expect(screen.queryByTestId("textarea-error")).not.toBeInTheDocument();
    });

    /**
     * @description Should not call onSubmit when isSubmitting is true (button disabled)
     * @scenario Component receives isSubmitting=true and user clicks Save
     * @expected onSubmit not called and save button is disabled
     */
    it("should not call onSubmit when already submitting", async () => {
      const user = userEvent.setup();
      const onSubmitMock = vi.fn();
      render(
        <EditCommentModal
          {...defaultProps}
          onSubmit={onSubmitMock}
          isSubmitting={true}
        />,
      );
      const saveButton = screen.getByTestId("button-primary");

      await user.click(saveButton);

      expect(onSubmitMock).not.toHaveBeenCalled();
      expect(saveButton).toBeDisabled();
    });
  });

  // ===========================================================================

  describe("closing behavior", () => {
    /**
     * @description Should call onClose when Cancel button clicked
     * @scenario User clicks Cancel button
     * @expected onClose called
     */
    it("should call onClose on Cancel button click", async () => {
      const user = userEvent.setup();
      const onCloseMock = vi.fn();
      render(<EditCommentModal {...defaultProps} onClose={onCloseMock} />);

      await user.click(screen.getByTestId("button-secondary"));

      expect(onCloseMock).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should prevent modal close when isSubmitting is true
     * @scenario User tries to close modal via overlay or Esc during submission
     * @expected onClose not called
     */
    it("should not close modal when isSubmitting is true", async () => {
      const user = userEvent.setup();
      const onCloseMock = vi.fn();
      render(
        <EditCommentModal
          {...defaultProps}
          onClose={onCloseMock}
          isSubmitting={true}
        />,
      );
      const overlayCloseButton = screen.getByTestId("modal-overlay-close");

      await user.click(overlayCloseButton);

      expect(onCloseMock).not.toHaveBeenCalled();
    });

    /**
     * @description Should display external error from prop in textarea error area
     * @scenario error prop is provided
     * @expected Error message shown
     */
    it("should display external error when provided", () => {
      const externalError = "Server error occurred";
      render(<EditCommentModal {...defaultProps} error={externalError} />);

      expect(screen.getByTestId("textarea-error")).toHaveTextContent(
        externalError,
      );
    });
  });

  // ===========================================================================

  describe("display of current comment", () => {
    /**
     * @description Should show current comment text when file.comment exists
     * @scenario file has a comment
     * @expected Element with current comment appears
     */
    it("should render current comment block when file.comment not empty", () => {
      render(<EditCommentModal {...defaultProps} />);

      expect(screen.getByText(/Текущий комментарий:/)).toBeInTheDocument();
      expect(screen.getByText(`"${mockFile.comment}"`)).toBeInTheDocument();
    });

    /**
     * @description Should not show current comment block when file.comment is empty
     * @scenario file.comment is null or empty string
     * @expected No current comment paragraph
     */
    it("should hide current comment block when file.comment is empty", () => {
      const fileWithoutComment: IFile = { ...mockFile, comment: "" };
      render(<EditCommentModal {...defaultProps} file={fileWithoutComment} />);

      expect(
        screen.queryByText(/Текущий комментарий:/),
      ).not.toBeInTheDocument();
    });
  });
});
