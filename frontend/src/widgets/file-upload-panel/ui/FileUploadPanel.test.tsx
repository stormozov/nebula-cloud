import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { useFileUploadPanel } from "../lib/useFileUploadPanel";
import { FileUploadPanel } from "./FileUploadPanel";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../lib/useFileUploadPanel");

const { toastSuccessMock, toastErrorMock } = vi.hoisted(() => ({
  toastSuccessMock: vi.fn(),
  toastErrorMock: vi.fn(),
}));

vi.mock("react-toastify", () => ({
  toast: {
    success: toastSuccessMock,
    error: toastErrorMock,
  },
}));

vi.mock("react-toastify", () => ({
  toast: {
    success: toastSuccessMock,
    error: toastErrorMock,
  },
}));

vi.mock("@/shared/ui", () => ({
  Button: ({
    children,
    ...props
  }: { children?: React.ReactNode } & Record<string, unknown>) => (
    <button {...props}>{children}</button>
  ),
  Icon: ({ name }: { name?: string }) => (
    <span data-testid={`icon-${name ?? ""}`}>{name}</span>
  ),
}));

vi.mock("@/features/file/file-upload", () => ({
  FileUploadItem: ({
    upload,
    onCancel,
    onRetry,
    onRemove,
  }: Record<string, unknown>) => {
    const id = (upload as { id: string }).id;

    return (
      <button
        type="button"
        data-testid={`file-upload-item-${id}`}
        onClick={() => {
          if (onCancel) (onCancel as (uploadId: string) => void)(id);
          if (onRetry) (onRetry as (uploadId: string) => void)(id);
          if (onRemove) (onRemove as (uploadId: string) => void)(id);
        }}
      />
    );
  },
}));

// =============================================================================
// TESTS
// =============================================================================

describe("FileUploadPanel", () => {
  const mockUseFileUploadPanel = useFileUploadPanel as unknown as Mock;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when panel is hidden and queue is empty", () => {
    /**
     * @description Should not render FileUploadPanel when it is hidden, queue is empty, and it is not closing
     * @scenario useFileUploadPanel returns isPanelVisible=false, queue.length=0, isClosing=false
     * @expected component returns null
     */
    it("should return null when panel is hidden and queue is empty", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [],
        isPanelVisible: false,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      const { container } = render(<FileUploadPanel />);

      // Assert
      expect(container).toBeEmptyDOMElement();
    });
  });

  describe("when queue has items", () => {
    const baseUpload = {
      id: "u1",
      file: {
        name: "a.txt",
        size: 1,
        type: "text/plain",
        lastModified: 1,
        comment: "",
      },
      progress: 50,
      status: "uploading",
      error: undefined,
      needsReupload: false,
    };

    /**
     * @description Should render panel title with uploading count when uploading exists
     * @scenario queue contains uploading item and stats.uploading > 0
     * @expected title shows 'Загрузка (count)'
     */
    it("should show uploading title when uploadingCount is greater than 0", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [baseUpload],
        isPanelVisible: true,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 1 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(screen.getByText("Загрузка (1)")).toBeInTheDocument();
    });

    /**
     * @description Should render 'Готово (completed/total)' title when queue is completed and there are no uploading items
     * @scenario isQueueCompleted=true, stats.uploading=0
     * @expected title shows completed and total counts
     */
    it("should show ready title with completed/total when queue is completed", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [
          {
            ...baseUpload,
            id: "u1",
            status: "success",
            progress: 100,
          },
          {
            ...baseUpload,
            id: "u2",
            status: "error",
            progress: 100,
            error: "Some error",
          },
        ],
        isPanelVisible: true,
        isQueueCompleted: true,
        stats: { success: 1, error: 1, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(screen.getByText("Готово (1/2)")).toBeInTheDocument();
      const titleElement = screen.getByText("Готово (1/2)");
      expect(
        within(titleElement).getByTestId("icon-check"),
      ).toBeInTheDocument();
    });

    /**
     * @description Should render 'Файлы (count)' title when queue is not completed and there are no uploading items
     * @scenario isQueueCompleted=false, stats.uploading=0
     * @expected title shows total queue length
     */
    it("should show files title when queue is not completed and uploadingCount is 0", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [baseUpload, { ...baseUpload, id: "u2" }],
        isPanelVisible: true,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(screen.getByText("Файлы (2)")).toBeInTheDocument();
    });

    /**
     * @description Should disable close button when canClosePanel is false and set correct title
     * @scenario canClosePanel=false
     * @expected close button is disabled
     */
    it("should disable close button when panel cannot be closed", () => {
      // Arrange
      const handleClose = vi.fn();
      mockUseFileUploadPanel.mockReturnValue({
        queue: [baseUpload],
        isPanelVisible: true,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 1 },
        isClosing: false,
        canClosePanel: false,
        handleCloseWithAnimation: handleClose,
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);
      const closeButton = screen.getByRole("button", { name: /закрыть/i });

      // Assert
      expect(closeButton).toBeDisabled();
    });

    /**
     * @description Should call handleCloseWithAnimation when close button is clicked
     * @scenario canClosePanel=true and user clicks close button
     * @expected handleCloseWithAnimation is called once
     */
    it("should call close handler when user clicks close button", async () => {
      // Arrange
      const handleClose = vi.fn();
      mockUseFileUploadPanel.mockReturnValue({
        queue: [baseUpload],
        isPanelVisible: true,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 1 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: handleClose,
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);
      const closeButton = screen.getByRole("button", { name: /закрыть/i });
      await userEvent.click(closeButton);

      // Assert
      expect(handleClose).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should call handleCloseWithAnimation when clear button is clicked
     * @scenario queue.length>0 shows footer and clear button exists
     * @expected handleCloseWithAnimation is called
     */
    it("should call close handler when user clicks clear button", async () => {
      // Arrange
      const handleClose = vi.fn();
      mockUseFileUploadPanel.mockReturnValue({
        queue: [baseUpload],
        isPanelVisible: true,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 1 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: handleClose,
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);
      const clearButton = screen.getByRole("button", { name: /очистить/i });
      await userEvent.click(clearButton);

      // Assert
      expect(handleClose).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should show success stats in footer when completedCount is provided
     * @scenario footer is rendered and stats.success equals 2
     * @expected success stat shows 2
     */
    it("should display success count in footer when uploads succeeded", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [
          { ...baseUpload, id: "u1", status: "success", progress: 100 },
          { ...baseUpload, id: "u2", status: "success", progress: 100 },
        ],
        isPanelVisible: true,
        isQueueCompleted: true,
        stats: { success: 2, error: 0, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(screen.getByText("2")).toBeInTheDocument();
    });

    /**
     * @description Should show error stats in footer when failedCount is greater than 0
     * @scenario stats.error=3
     * @expected error stat shows 3
     */
    it("should display error count in footer when uploads failed", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [
          {
            ...baseUpload,
            id: "u1",
            status: "error",
            progress: 100,
            error: "err",
          },
          {
            ...baseUpload,
            id: "u2",
            status: "error",
            progress: 100,
            error: "err",
          },
        ],
        isPanelVisible: true,
        isQueueCompleted: true,
        stats: { success: 0, error: 3, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(screen.getByText("3")).toBeInTheDocument();
    });

    /**
     * @description Should call handleCancel/Retry/Remove handlers for each FileUploadItem when FileUploadItem triggers callbacks
     * @scenario render queue with items and mock FileUploadItem calls all handlers
     * @expected all corresponding callbacks are called with upload id
     */
    it("should pass callbacks to FileUploadItem so that actions call handlers with upload id", async () => {
      // Arrange
      const handleCancel = vi.fn();
      const handleRetry = vi.fn();
      const handleRemove = vi.fn();

      mockUseFileUploadPanel.mockReturnValue({
        queue: [baseUpload],
        isPanelVisible: true,
        isQueueCompleted: false,
        stats: { success: 0, error: 0, uploading: 1 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel,
        handleRetry,
        handleRemove,
      });

      // Act
      render(<FileUploadPanel />);
      await userEvent.click(screen.getByTestId("file-upload-item-u1"));

      // Assert
      expect(handleCancel).toHaveBeenCalledWith("u1");
      expect(handleRetry).toHaveBeenCalledWith("u1");
      expect(handleRemove).toHaveBeenCalledWith("u1");
    });
  });

  describe("when queue is completed", () => {
    const uploadingEmptyQueue = [] as unknown[];

    /**
     * @description Should show toast.success when queue completed without failed uploads
     * @scenario isQueueCompleted=true, failedCount=0
     * @expected toast.success is called with 'Файлы успешно загружены'
     */
    it("should show success toast when queue is completed with no errors", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: uploadingEmptyQueue,
        isPanelVisible: true,
        isQueueCompleted: true,
        stats: { success: 2, error: 0, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(toastSuccessMock).toHaveBeenCalledWith("Файлы успешно загружены");
    });

    /**
     * @description Should prefer storage limit error text when it exists in queue.error
     * @scenario isQueueCompleted=true, failedCount>0, one upload.error contains 'Превышен лимит хранилища'
     * @expected toast.error called with storageError.error
     */
    it("should show storage limit toast error when storage limit error exists in queue", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [
          {
            id: "u1",
            file: {
              name: "a.txt",
              size: 1,
              type: "text/plain",
              lastModified: 1,
              comment: "",
            },
            progress: 100,
            status: "error",
            error: "Превышен лимит хранилища: exceeded",
            needsReupload: false,
          },
        ],
        isPanelVisible: true,
        isQueueCompleted: true,
        stats: { success: 0, error: 1, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(toastErrorMock).toHaveBeenCalledWith(
        "Превышен лимит хранилища: exceeded",
      );
    });

    /**
     * @description Should show generic file upload errors toast when failedCount>0 and no storage limit error exists
     * @scenario isQueueCompleted=true, failedCount>0, none upload.error includes storage limit text
     * @expected toast.error called with 'Ошибки загрузки файлов (failedCount)'
     */
    it("should show generic upload errors toast when queue has failures without storage limit error", () => {
      // Arrange
      mockUseFileUploadPanel.mockReturnValue({
        queue: [
          {
            id: "u1",
            file: {
              name: "a.txt",
              size: 1,
              type: "text/plain",
              lastModified: 1,
              comment: "",
            },
            progress: 100,
            status: "error",
            error: "Some other error",
            needsReupload: false,
          },
        ],
        isPanelVisible: true,
        isQueueCompleted: true,
        stats: { success: 0, error: 2, uploading: 0 },
        isClosing: false,
        canClosePanel: true,
        handleCloseWithAnimation: vi.fn(),
        handleCancel: vi.fn(),
        handleRetry: vi.fn(),
        handleRemove: vi.fn(),
      });

      // Act
      render(<FileUploadPanel />);

      // Assert
      expect(toastErrorMock).toHaveBeenCalledWith("Ошибки загрузки файлов (2)");
    });
  });
});
