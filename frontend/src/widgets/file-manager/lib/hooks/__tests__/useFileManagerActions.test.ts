/** biome-ignore-all lint/suspicious/noExplicitAny: <for tests> */

import { renderHook } from "@testing-library/react";
import { toast } from "react-toastify";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  vi,
} from "vitest";

import { useAppDispatch } from "@/app/store/hooks";
import {
  downloadFileFromApi,
  type IFile,
  useDeleteFileMutation,
  useDeletePublicLinkMutation,
  useGeneratePublicLinkMutation,
  useRenameFileMutation,
  useUpdateCommentMutation,
} from "@/entities/file";
import { userApi } from "@/entities/user";
import { camelToSnake } from "@/shared/utils";

import { useFileManagerActions } from "../useFileManagerActions";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/app/store/hooks", () => ({
  useAppDispatch: vi.fn(),
}));

vi.mock("@/entities/file", () => ({
  downloadFileFromApi: vi.fn(),
  useDeleteFileMutation: vi.fn(),
  useDeletePublicLinkMutation: vi.fn(),
  useGeneratePublicLinkMutation: vi.fn(),
  useRenameFileMutation: vi.fn(),
  useUpdateCommentMutation: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  userApi: {
    util: {
      invalidateTags: vi.fn(),
    },
  },
}));

vi.mock("@/shared/utils", () => ({
  camelToSnake: vi.fn((obj) => obj),
}));

vi.mock("react-toastify", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
  },
}));

// =============================================================================
// TESTS HELPERS
// =============================================================================

const createMockFile = (overrides?: Partial<IFile>): IFile => ({
  id: 1,
  originalName: "test.txt",
  comment: "initial comment",
  size: 1024,
  sizeFormatted: "1 KB",
  uploadedAt: "2025-01-01T00:00:00Z",
  lastDownloaded: null,
  hasPublicLink: false,
  publicLinkUrl: null,
  downloadUrl: "https://example.com/download/1",
  ...overrides,
});

// =============================================================================
// TESTS
// =============================================================================

describe("useFileManagerActions", () => {
  let mockDispatch: Mock;
  let mockDeleteFile: Mock;
  let mockRenameFile: Mock;
  let mockUpdateComment: Mock;
  let mockGeneratePublicLink: Mock;
  let mockDeletePublicLink: Mock;
  let closeModalMock: Mock;
  let resetPaginationMock: Mock;
  let selectedFile: IFile | null;

  beforeEach(() => {
    vi.clearAllMocks();

    mockDispatch = vi.fn();
    (useAppDispatch as Mock).mockReturnValue(mockDispatch);

    mockDeleteFile = vi
      .fn()
      .mockReturnValue({ unwrap: vi.fn().mockResolvedValue(undefined) });
    mockRenameFile = vi
      .fn()
      .mockReturnValue({ unwrap: vi.fn().mockResolvedValue(undefined) });
    mockUpdateComment = vi
      .fn()
      .mockReturnValue({ unwrap: vi.fn().mockResolvedValue(undefined) });
    mockGeneratePublicLink = vi
      .fn()
      .mockReturnValue({ unwrap: vi.fn().mockResolvedValue(undefined) });
    mockDeletePublicLink = vi
      .fn()
      .mockReturnValue({ unwrap: vi.fn().mockResolvedValue(undefined) });

    (useDeleteFileMutation as Mock).mockReturnValue([
      mockDeleteFile,
      { isLoading: false },
    ]);
    (useRenameFileMutation as Mock).mockReturnValue([
      mockRenameFile,
      { isLoading: false },
    ]);
    (useUpdateCommentMutation as Mock).mockReturnValue([
      mockUpdateComment,
      { isLoading: false },
    ]);
    (useGeneratePublicLinkMutation as Mock).mockReturnValue([
      mockGeneratePublicLink,
      { isLoading: false },
    ]);
    (useDeletePublicLinkMutation as Mock).mockReturnValue([
      mockDeletePublicLink,
      { isLoading: false },
    ]);

    closeModalMock = vi.fn();
    resetPaginationMock = vi.fn();
    selectedFile = createMockFile();

    (camelToSnake as Mock).mockImplementation((obj) => obj);
  });

  describe("delete file", () => {
    describe("when selectedFile exists", () => {
      /**
       * @description Should call deleteFile mutation, reset pagination, close modal, invalidate cache and show success toast
       * @scenario User confirms deletion, selectedFile is present
       * @expected deleteFile called with file id, resetPagination called, closeModal called with 'delete', dispatch invalidates UserStorage, toast.success called
       */
      it("should delete file and perform all cleanup actions", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleDeleteConfirm();

        // Assert
        expect(mockDeleteFile).toHaveBeenCalledWith(selectedFile?.id);
        expect(resetPaginationMock).toHaveBeenCalled();
        expect(closeModalMock).toHaveBeenCalledWith("delete");
        expect(mockDispatch).toHaveBeenCalledWith(
          userApi.util.invalidateTags(["UserStorage"]),
        );
        expect(toast.success).toHaveBeenCalledWith("Файл успешно удален");
      });

      /**
       * @description Should show error toast when deleteFile mutation rejects
       * @scenario User confirms deletion but API call fails
       * @expected toast.error called with error message, closeModal not called
       */
      it("should show error toast when delete fails", async () => {
        // Arrange
        mockDeleteFile.mockReturnValue({
          unwrap: vi.fn().mockRejectedValue(new Error("Network error")),
        });
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleDeleteConfirm();

        // Assert
        expect(toast.error).toHaveBeenCalledWith("Не удалось удалить файл");
        expect(closeModalMock).not.toHaveBeenCalled();
      });
    });

    describe("when selectedFile is null", () => {
      /**
       * @description Should not call deleteFile mutation when no file is selected
       * @scenario User triggers delete but selectedFile === null
       * @expected deleteFile not called, no side effects
       */
      it("should not call deleteFile when selectedFile is null", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile: null,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleDeleteConfirm();

        // Assert
        expect(mockDeleteFile).not.toHaveBeenCalled();
        expect(resetPaginationMock).not.toHaveBeenCalled();
        expect(closeModalMock).not.toHaveBeenCalled();
      });
    });
  });

  describe("rename file", () => {
    const newName = "renamed.txt";

    describe("when selectedFile exists", () => {
      /**
       * @description Should call renameFile mutation with transformed payload, close modal and show success toast
       * @scenario User submits new name, selectedFile is present
       * @expected renameFile called with id and camelToSnake result, closeModal called with 'rename', toast.success called
       */
      it("should rename file and close modal", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleRenameSubmit(newName);

        // Assert
        expect(camelToSnake).toHaveBeenCalledWith({ original_name: newName });
        expect(mockRenameFile).toHaveBeenCalledWith({
          id: selectedFile?.id,
          data: { original_name: newName },
        });
        expect(closeModalMock).toHaveBeenCalledWith("rename");
        expect(toast.success).toHaveBeenCalledWith("Файл успешно переименован");
      });

      /**
       * @description Should show error toast when renameFile mutation rejects
       * @scenario User submits new name but API call fails
       * @expected toast.error called, closeModal not called
       */
      it("should show error toast when rename fails", async () => {
        // Arrange
        mockRenameFile.mockReturnValue({
          unwrap: vi.fn().mockRejectedValue(new Error()),
        });
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleRenameSubmit(newName);

        // Assert
        expect(toast.error).toHaveBeenCalledWith(
          "Не удалось переименовать файл",
        );
        expect(closeModalMock).not.toHaveBeenCalled();
      });
    });

    describe("when selectedFile is null", () => {
      /**
       * @description Should not call renameFile when no file is selected
       * @scenario User triggers rename but selectedFile === null
       * @expected renameFile not called
       */
      it("should not call renameFile when selectedFile is null", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile: null,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleRenameSubmit(newName);

        // Assert
        expect(mockRenameFile).not.toHaveBeenCalled();
      });
    });
  });

  describe("comment update", () => {
    const newComment = "updated comment";

    describe("when selectedFile exists", () => {
      /**
       * @description Should call updateComment mutation with comment data, close modal and show success toast
       * @scenario User submits new comment, selectedFile is present
       * @expected updateComment called with id and comment, closeModal called with 'comment', toast.success called
       */
      it("should update comment and close modal", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleCommentUpdate(newComment);

        // Assert
        expect(mockUpdateComment).toHaveBeenCalledWith({
          id: selectedFile?.id,
          data: { comment: newComment },
        });
        expect(closeModalMock).toHaveBeenCalledWith("comment");
        expect(toast.success).toHaveBeenCalledWith(
          "Комментарий успешно обновлен",
        );
      });

      /**
       * @description Should show error toast when updateComment mutation rejects
       * @scenario User submits comment but API call fails
       * @expected toast.error called, closeModal not called
       */
      it("should show error toast when comment update fails", async () => {
        // Arrange
        mockUpdateComment.mockReturnValue({
          unwrap: vi.fn().mockRejectedValue(new Error()),
        });
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleCommentUpdate(newComment);

        // Assert
        expect(toast.error).toHaveBeenCalledWith(
          "Не удалось обновить комментарии",
        );
        expect(closeModalMock).not.toHaveBeenCalled();
      });
    });

    describe("when selectedFile is null", () => {
      /**
       * @description Should not call updateComment when no file is selected
       * @scenario User triggers comment update but selectedFile === null
       * @expected updateComment not called
       */
      it("should not call updateComment when selectedFile is null", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile: null,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleCommentUpdate("comment");

        // Assert
        expect(mockUpdateComment).not.toHaveBeenCalled();
      });
    });
  });

  describe("download file", () => {
    /**
     * @description Should call downloadFileFromApi with file id and original name, then show info toast
     * @scenario User clicks download on a file
     * @expected downloadFileFromApi called with correct arguments, toast.info called
     */
    it("should download file and show info toast", async () => {
      // Arrange
      const file = createMockFile();
      const { result } = renderHook(() =>
        useFileManagerActions({
          selectedFile,
          closeModal: closeModalMock,
          resetPagination: resetPaginationMock,
        }),
      );

      // Act
      await result.current.handleDownloadFile(file);

      // Assert
      expect(downloadFileFromApi).toHaveBeenCalledWith(
        file.id,
        file.originalName,
      );
      expect(toast.info).toHaveBeenCalledWith("Началось скачивание файла");
    });

    /**
     * @description Should show error toast when downloadFileFromApi throws
     * @scenario Download API call fails
     * @expected toast.error called
     */
    it("should show error toast when download fails", async () => {
      // Arrange
      const file = createMockFile();
      (downloadFileFromApi as Mock).mockRejectedValue(new Error());
      const { result } = renderHook(() =>
        useFileManagerActions({
          selectedFile,
          closeModal: closeModalMock,
          resetPagination: resetPaginationMock,
        }),
      );

      // Act
      await result.current.handleDownloadFile(file);

      // Assert
      expect(toast.error).toHaveBeenCalledWith("Не удалось скачать файл");
    });
  });

  describe("generate public link", () => {
    describe("when selectedFile exists", () => {
      /**
       * @description Should call generatePublicLink mutation with file id
       * @scenario User requests public link generation, selectedFile is present
       * @expected generatePublicLink called with selectedFile.id
       */
      it("should call generatePublicLink with file id", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleGeneratePublicLink();

        // Assert
        expect(mockGeneratePublicLink).toHaveBeenCalledWith(selectedFile?.id);
      });

      /**
       * @description Should show error toast when generatePublicLink mutation rejects
       * @scenario API call fails
       * @expected toast.error called
       */
      it("should show error toast when generation fails", async () => {
        // Arrange
        mockGeneratePublicLink.mockReturnValue({
          unwrap: vi.fn().mockRejectedValue(new Error()),
        });
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleGeneratePublicLink();

        // Assert
        expect(toast.error).toHaveBeenCalledWith(
          "Не удалось сгенерировать ссылку",
        );
      });
    });

    describe("when selectedFile is null", () => {
      /**
       * @description Should not call generatePublicLink when no file is selected
       * @scenario User triggers link generation but selectedFile === null
       * @expected generatePublicLink not called
       */
      it("should not call generatePublicLink when selectedFile is null", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile: null,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleGeneratePublicLink();

        // Assert
        expect(mockGeneratePublicLink).not.toHaveBeenCalled();
      });
    });
  });

  describe("delete public link", () => {
    describe("when selectedFile exists", () => {
      /**
       * @description Should call deletePublicLink mutation, close modal and show success toast
       * @scenario User requests public link deletion, selectedFile is present
       * @expected deletePublicLink called with file id, closeModal called with 'link', toast.success called
       */
      it("should delete public link, close modal and show success", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleDeletePublicLink();

        // Assert
        expect(mockDeletePublicLink).toHaveBeenCalledWith(selectedFile?.id);
        expect(closeModalMock).toHaveBeenCalledWith("link");
        expect(toast.success).toHaveBeenCalledWith(
          "Публичная ссылка успешно удалена",
        );
      });

      /**
       * @description Should show error toast when deletePublicLink mutation rejects
       * @scenario API call fails
       * @expected toast.error called, closeModal not called
       */
      it("should show error toast when deletion fails", async () => {
        // Arrange
        mockDeletePublicLink.mockReturnValue({
          unwrap: vi.fn().mockRejectedValue(new Error()),
        });
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleDeletePublicLink();

        // Assert
        expect(toast.error).toHaveBeenCalledWith(
          "Не удалось удалить публичную ссылку",
        );
        expect(closeModalMock).not.toHaveBeenCalled();
      });
    });

    describe("when selectedFile is null", () => {
      /**
       * @description Should not call deletePublicLink when no file is selected
       * @scenario User triggers link deletion but selectedFile === null
       * @expected deletePublicLink not called
       */
      it("should not call deletePublicLink when selectedFile is null", async () => {
        // Arrange
        const { result } = renderHook(() =>
          useFileManagerActions({
            selectedFile: null,
            closeModal: closeModalMock,
            resetPagination: resetPaginationMock,
          }),
        );

        // Act
        await result.current.handleDeletePublicLink();

        // Assert
        expect(mockDeletePublicLink).not.toHaveBeenCalled();
      });
    });
  });

  describe("copy public link", () => {
    let originalClipboardDescriptor: PropertyDescriptor | undefined;

    beforeEach(() => {
      originalClipboardDescriptor = Object.getOwnPropertyDescriptor(
        navigator,
        "clipboard",
      );
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        writable: true,
        value: {
          writeText: vi.fn().mockResolvedValue(undefined),
        },
      });
    });

    afterEach(() => {
      if (originalClipboardDescriptor) {
        Object.defineProperty(
          navigator,
          "clipboard",
          originalClipboardDescriptor,
        );
      } else {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        delete (navigator as any).clipboard;
      }
    });

    /**
     * @description Should copy URL to clipboard and show success toast
     * @scenario User clicks copy link with valid URL
     * @expected clipboard.writeText called with URL, toast.success called
     */
    it("should copy URL to clipboard and show success toast", async () => {
      // Arrange
      const url = "https://example.com/share/123";
      const { result } = renderHook(() =>
        useFileManagerActions({
          selectedFile,
          closeModal: closeModalMock,
          resetPagination: resetPaginationMock,
        }),
      );

      // Act
      await result.current.handleCopyPublicLink(url);

      // Assert
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(url);
      expect(toast.success).toHaveBeenCalledWith("Ссылка скопирована");
    });

    /**
     * @description Should show error toast when clipboard write fails
     * @scenario navigator.clipboard.writeText rejects
     * @expected toast.error called
     */
    it("should show error toast when copy fails", async () => {
      // Arrange
      (navigator.clipboard.writeText as Mock).mockRejectedValue(new Error());
      const { result } = renderHook(() =>
        useFileManagerActions({
          selectedFile,
          closeModal: closeModalMock,
          resetPagination: resetPaginationMock,
        }),
      );

      // Act
      await result.current.handleCopyPublicLink("https://example.com");

      // Assert
      expect(toast.error).toHaveBeenCalledWith("Не удалось скопировать ссылку");
    });
  });

  describe("loading states", () => {
    /**
     * @description Should return loading flags from RTK Query hooks
     * @scenario Mutations are in loading state
     * @expected isDeleting, isRenaming, etc. reflect mutation isLoading values
     */
    it("should expose loading states from mutations", () => {
      // Arrange
      (useDeleteFileMutation as Mock).mockReturnValue([
        vi.fn(),
        { isLoading: true },
      ]);
      (useRenameFileMutation as Mock).mockReturnValue([
        vi.fn(),
        { isLoading: true },
      ]);
      (useUpdateCommentMutation as Mock).mockReturnValue([
        vi.fn(),
        { isLoading: true },
      ]);
      (useGeneratePublicLinkMutation as Mock).mockReturnValue([
        vi.fn(),
        { isLoading: true },
      ]);
      (useDeletePublicLinkMutation as Mock).mockReturnValue([
        vi.fn(),
        { isLoading: true },
      ]);

      // Act
      const { result } = renderHook(() =>
        useFileManagerActions({
          selectedFile,
          closeModal: closeModalMock,
          resetPagination: resetPaginationMock,
        }),
      );

      // Assert
      expect(result.current.isDeleting).toBe(true);
      expect(result.current.isRenaming).toBe(true);
      expect(result.current.isUpdatingComment).toBe(true);
      expect(result.current.isGeneratingLink).toBe(true);
      expect(result.current.isDeletingLink).toBe(true);
    });
  });
});
