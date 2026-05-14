import { render, screen } from "@testing-library/react";
import type { Mock } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useAppDispatch, useAppSelector } from "@/app/store/hooks";
import type { IFile } from "@/entities/file";
import { selectIsQueueCompleted } from "@/entities/file-upload";
import { userApi } from "@/entities/user";
import { useFileSearch } from "@/features/file/file-search";
import { useStorageUsage } from "@/features/storage-usage";
import { ListSkeleton } from "@/shared/ui";

import { useFileManagerActions } from "../../lib/hooks/useFileManagerActions";
import { useFileManagerModals } from "../../lib/hooks/useFileManagerModals";
import { useFileManagerPagination } from "../../lib/hooks/useFileManagerPagination";
import { FileManager } from "../FileManager";
import { FileManagerContent } from "../FileManagerContent";
import { FileManagerDropzone } from "../FileManagerDropzone";
import { FileManagerHeader } from "../FileManagerHeader";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/app/store/hooks", () => ({
  useAppDispatch: vi.fn(),
  useAppSelector: vi.fn(),
}));

vi.mock("@/entities/file-upload", () => ({
  selectIsQueueCompleted: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  userApi: {
    util: {
      invalidateTags: vi.fn(),
    },
  },
}));

// -- MOCKS FOR FEATURES -------------------------------------------------------

vi.mock("@/features/file/file-search", () => ({
  useFileSearch: vi.fn(),
}));

vi.mock("@/features/storage-usage", () => ({
  useStorageUsage: vi.fn(),
  StorageProgressBar: vi.fn((props) => (
    <div data-testid="storage-progress-bar" {...props} />
  )),
}));

vi.mock("@/features/file/file-comment", () => ({
  EditCommentModal: vi.fn(
    ({ isOpen }) =>
      isOpen && <div data-testid="edit-comment-modal">Edit Comment Modal</div>,
  ),
}));

vi.mock("@/features/file/file-delete", () => ({
  DeleteFileModal: vi.fn(
    ({ isOpen }) =>
      isOpen && <div data-testid="delete-file-modal">Delete File Modal</div>,
  ),
}));

vi.mock("@/features/file/file-image-preview", () => ({
  ImageViewerModal: vi.fn(
    ({ isOpen }) =>
      isOpen && <div data-testid="image-viewer-modal">Image Viewer Modal</div>,
  ),
}));

vi.mock("@/features/file/file-public-link", () => ({
  PublicLinkModal: vi.fn(
    ({ isOpen }) =>
      isOpen && <div data-testid="public-link-modal">Public Link Modal</div>,
  ),
}));

vi.mock("@/features/file/file-rename", () => ({
  RenameFileModal: vi.fn(
    ({ isOpen }) =>
      isOpen && <div data-testid="rename-file-modal">Rename File Modal</div>,
  ),
}));

// -- MOCKS FOR SHARED ---------------------------------------------------------

vi.mock("@/shared/ui", () => ({
  ListSkeleton: vi.fn(() => <div data-testid="list-skeleton">Loading...</div>),
}));

vi.mock("@/shared/configs/file-list.json", () => ({
  default: { header_columns: [] },
}));

vi.mock("@/shared/utils", async () => {
  const actual = await vi.importActual("@/shared/utils");
  return {
    ...actual,
    getErrorMessage: vi.fn((error) => error?.message || ""),
    isImageFile: vi.fn((file) => file?.mimeType?.startsWith("image/")),
  };
});

// -- MOCKS FOR LIB ------------------------------------------------------------

vi.mock("../../lib/hooks/useFileManagerPagination", () => ({
  useFileManagerPagination: vi.fn(),
}));

vi.mock("../../lib/hooks/useFileManagerModals", () => ({
  useFileManagerModals: vi.fn(),
}));

vi.mock("../../lib/hooks/useFileManagerActions", () => ({
  useFileManagerActions: vi.fn(),
}));

// -- MOCKS FOR UI -------------------------------------------------------------

vi.mock("../FileManagerHeader", () => ({
  FileManagerHeader: vi.fn((props) => (
    <div data-testid="file-manager-header" {...props} />
  )),
}));

vi.mock("../FileManagerDropzone", () => ({
  FileManagerDropzone: vi.fn((props) => (
    <div data-testid="file-manager-dropzone" {...props} />
  )),
}));

vi.mock("../FileManagerContent", () => ({
  FileManagerContent: vi.fn((props) => (
    <div data-testid="file-manager-content" {...props} />
  )),
}));

// =============================================================================
// HELPERS
// =============================================================================

const mockDispatch = vi.fn();
const mockUseAppDispatch = useAppDispatch as Mock;
const mockUseAppSelector = useAppSelector as Mock;
const mockSelectIsQueueCompleted = selectIsQueueCompleted as Mock;
const mockUserApiInvalidateTags = userApi.util
  .invalidateTags as unknown as Mock;

const mockUseFileSearch = useFileSearch as Mock;
const mockUseStorageUsage = useStorageUsage as Mock;
const mockUseFileManagerPagination = useFileManagerPagination as Mock;
const mockUseFileManagerModals = useFileManagerModals as Mock;
const mockUseFileManagerActions = useFileManagerActions as Mock;

const mockFileManagerHeader = FileManagerHeader as Mock;
const mockFileManagerDropzone = FileManagerDropzone as Mock;
const mockFileManagerContent = FileManagerContent as Mock;

const createMockFile = (id: number, overrides = {}): IFile => ({
  id,
  originalName: `test-${id}.jpg`,
  size: 1024,
  hasPublicLink: false,
  publicLinkUrl: null,
  uploadedAt: "2025-01-01T00:00:00Z",
  sizeFormatted: "1 KB",
  lastDownloaded: null,
  downloadUrl: `https://example.com/download/${id}`,
  comment: null,
  ...overrides,
});

const defaultPaginationMock = {
  files: [],
  isLoading: false,
  isFetching: false,
  error: null,
  hasNextPage: false,
  isDataReady: true,
  currentPageFilesCount: 0,
  loadMore: vi.fn(),
  resetPagination: vi.fn(),
};

const defaultModalsMock = {
  modalOpen: {
    delete: false,
    rename: false,
    comment: false,
    link: false,
    imageViewer: false,
  },
  selectedFile: null,
  selectedImageFile: null,
  openModal: vi.fn(),
  closeModal: vi.fn(),
  setSelectedImageFile: vi.fn(),
  updateSelectedFile: vi.fn(),
};

const defaultActionsMock = {
  isDeleting: false,
  isRenaming: false,
  isUpdatingComment: false,
  isGeneratingLink: false,
  isDeletingLink: false,
  handleDeleteConfirm: vi.fn(),
  handleRenameSubmit: vi.fn(),
  handleCommentUpdate: vi.fn(),
  handleDownloadFile: vi.fn(),
  handleGeneratePublicLink: vi.fn(),
  handleDeletePublicLink: vi.fn(),
  handleCopyPublicLink: vi.fn(),
};

const defaultStorageUsageMock = {
  used: 100,
  limit: 1000,
  usedFormatted: "100 KB",
  limitFormatted: "1 MB",
  percent: 10,
  isLoading: false,
};

// =============================================================================
// TESTS
// =============================================================================

describe("FileManager", () => {
  beforeEach(() => {
    mockDispatch.mockReturnValue({});
    mockUseAppDispatch.mockReturnValue(mockDispatch);
    mockUseAppSelector.mockImplementation((selector) => {
      if (selector === selectIsQueueCompleted) return false;
      return undefined;
    });
    mockSelectIsQueueCompleted.mockReturnValue(false);

    mockUseFileSearch.mockReturnValue({
      searchTerm: "",
      setSearchTerm: vi.fn(),
      debouncedSearchTerm: "",
    });

    mockUseStorageUsage.mockReturnValue(defaultStorageUsageMock);
    mockUseFileManagerPagination.mockReturnValue(defaultPaginationMock);
    mockUseFileManagerModals.mockReturnValue(defaultModalsMock);
    mockUseFileManagerActions.mockReturnValue(defaultActionsMock);

    mockFileManagerHeader.mockImplementation((props) => (
      <div data-testid="file-manager-header" {...props} />
    ));
    mockFileManagerDropzone.mockImplementation((props) => (
      <div data-testid="file-manager-dropzone" {...props} />
    ));
    mockFileManagerContent.mockImplementation((props) => (
      <div data-testid="file-manager-content" {...props} />
    ));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  // ---------------------------------------------------------------------------
  // RENDERING
  // ---------------------------------------------------------------------------

  describe("rendering", () => {
    /**
     * @description Renders main container and all sub components
     * @scenario Default props (isAdmin=false, no userId)
     * @expected Header, dropzone, content components are rendered
     */
    it("should render header, dropzone and content", () => {
      // Arrange
      // Act
      render(<FileManager />);

      // Assert
      expect(screen.getByTestId("file-manager-header")).toBeInTheDocument();
      expect(screen.getByTestId("file-manager-dropzone")).toBeInTheDocument();
      expect(screen.getByTestId("file-manager-content")).toBeInTheDocument();
    });

    /**
     * @description Passes correct props to FileManagerHeader
     * @scenario isAdmin=true, userId=123, searchTerm='test'
     * @expected Header receives isAdmin, userId, storageWidget, searchTerm, onSearchChange
     */
    it("should pass correct props to FileManagerHeader", () => {
      // Arrange
      const mockSetSearchTerm = vi.fn();
      const mockResetPagination = vi.fn();
      mockUseFileSearch.mockReturnValue({
        searchTerm: "test search",
        setSearchTerm: mockSetSearchTerm,
        debouncedSearchTerm: "test search",
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        resetPagination: mockResetPagination,
      });
      mockUseStorageUsage.mockReturnValue({
        ...defaultStorageUsageMock,
        isLoading: false,
      });

      // Act
      render(<FileManager isAdmin={true} userId={123} />);

      // Assert
      expect(mockFileManagerHeader).toHaveBeenCalledTimes(1);
      const headerProps = mockFileManagerHeader.mock.calls[0][0];
      expect(headerProps.isAdmin).toBe(true);
      expect(headerProps.userId).toBe(123);
      expect(headerProps.searchTerm).toBe("test search");
      expect(typeof headerProps.onSearchChange).toBe("function");
    });

    /**
     * @description Passes correct props to FileManagerContent
     * @scenario hasNextPage=true, isFetching=true, loadMore function provided
     * @expected Content receives hasNextPage, isFetching, loadMore, fileListProps
     */
    it("should pass correct props to FileManagerContent", () => {
      // Arrange
      const mockLoadMore = vi.fn();
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        hasNextPage: true,
        isFetching: true,
        loadMore: mockLoadMore,
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(mockFileManagerContent).toHaveBeenCalledTimes(1);
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      expect(contentProps.hasNextPage).toBe(true);
      expect(contentProps.isFetching).toBe(true);
      expect(contentProps.loadMore).toBe(mockLoadMore);
      expect(contentProps.fileListProps).toBeDefined();
    });

    /**
     * @description Renders storage progress bar when storage data is loaded
     * @scenario isStorageLoading=false
     * @expected StorageProgressBar component is rendered inside header
     */
    it("should render storage progress bar when storage is not loading", () => {
      // Arrange
      mockUseStorageUsage.mockReturnValue(defaultStorageUsageMock);

      // Act
      render(<FileManager />);

      // Assert
      const headerProps = mockFileManagerHeader.mock.calls[0][0];
      expect(headerProps.storageWidget).toBeTruthy();
      // We can't directly test StorageProgressBar because it's inside the widget,
      // but we know it's passed as storageWidget
    });

    /**
     * @description Does not render storage widget when storage is loading
     * @scenario isStorageLoading=true
     * @expected storageWidget is null
     */
    it("should not render storage widget when storage is loading", () => {
      // Arrange
      mockUseStorageUsage.mockReturnValue({
        ...defaultStorageUsageMock,
        isLoading: true,
      });

      // Act
      render(<FileManager />);

      // Assert
      const headerProps = mockFileManagerHeader.mock.calls[0][0];
      expect(headerProps.storageWidget).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // DROPZONE VISIBILITY LOGIC
  // ---------------------------------------------------------------------------

  describe("dropzone visibility logic", () => {
    /**
     * @description Shows dropzone when conditions are met: non-admin, no search, no files, no error, data ready
     * @scenario isAdmin=false, debouncedSearchTerm='', currentPageFilesCount=0, error=null, isLoading=false, isFetching=false, isDataReady=true
     * @expected FileManagerDropzone receives isVisible=true
     */
    it("should show dropzone when all conditions are true", () => {
      // Arrange
      mockUseFileSearch.mockReturnValue({
        searchTerm: "",
        setSearchTerm: vi.fn(),
        debouncedSearchTerm: "",
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        currentPageFilesCount: 0,
        error: null,
        isLoading: false,
        isFetching: false,
        isDataReady: true,
      });

      // Act
      render(<FileManager isAdmin={false} />);

      // Assert
      expect(mockFileManagerDropzone).toHaveBeenCalledTimes(1);
      const dropzoneProps = mockFileManagerDropzone.mock.calls[0][0];
      expect(dropzoneProps.isVisible).toBe(true);
    });

    /**
     * @description Hides dropzone when user is admin
     * @scenario isAdmin=true
     * @expected Dropzone receives isVisible=false
     */
    it("should hide dropzone when user is admin", () => {
      // Arrange
      mockUseFileSearch.mockReturnValue({
        searchTerm: "",
        setSearchTerm: vi.fn(),
        debouncedSearchTerm: "",
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        currentPageFilesCount: 0,
        error: null,
        isLoading: false,
        isFetching: false,
        isDataReady: true,
      });

      // Act
      render(<FileManager isAdmin={true} />);

      // Assert
      const dropzoneProps = mockFileManagerDropzone.mock.calls[0][0];
      expect(dropzoneProps.isVisible).toBe(false);
    });

    /**
     * @description Hides dropzone when search term exists
     * @scenario debouncedSearchTerm='something'
     * @expected isVisible=false
     */
    it("should hide dropzone when search term is not empty", () => {
      // Arrange
      mockUseFileSearch.mockReturnValue({
        searchTerm: "test",
        setSearchTerm: vi.fn(),
        debouncedSearchTerm: "test",
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        currentPageFilesCount: 0,
        error: null,
        isLoading: false,
        isFetching: false,
        isDataReady: true,
      });

      // Act
      render(<FileManager isAdmin={false} />);

      // Assert
      const dropzoneProps = mockFileManagerDropzone.mock.calls[0][0];
      expect(dropzoneProps.isVisible).toBe(false);
    });

    /**
     * @description Hides dropzone when there are files on current page
     * @scenario currentPageFilesCount > 0
     * @expected isVisible=false
     */
    it("should hide dropzone when currentPageFilesCount > 0", () => {
      // Arrange
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        currentPageFilesCount: 5,
        error: null,
        isLoading: false,
        isFetching: false,
        isDataReady: true,
      });

      // Act
      render(<FileManager isAdmin={false} />);

      // Assert
      const dropzoneProps = mockFileManagerDropzone.mock.calls[0][0];
      expect(dropzoneProps.isVisible).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // INTERACTIONS AND HANDLERS
  // ---------------------------------------------------------------------------

  describe("interactions and handlers", () => {
    /**
     * @description Calls setSearchTerm and resetPagination when search term changes
     * @scenario onSearchChange triggered from header
     * @expected setSearchTerm called with new value, resetPagination called
     */
    it("should update search term and reset pagination on search change", () => {
      // Arrange
      const mockSetSearchTerm = vi.fn();
      const mockResetPagination = vi.fn();
      mockUseFileSearch.mockReturnValue({
        searchTerm: "",
        setSearchTerm: mockSetSearchTerm,
        debouncedSearchTerm: "",
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        resetPagination: mockResetPagination,
      });

      render(<FileManager />);
      const headerProps = mockFileManagerHeader.mock.calls[0][0];
      const onSearchChange = headerProps.onSearchChange;

      // Act
      onSearchChange("new search");

      // Assert
      expect(mockSetSearchTerm).toHaveBeenCalledWith("new search");
      expect(mockResetPagination).toHaveBeenCalled();
    });

    /**
     * @description Opens image viewer modal when view handler is called with image file
     * @scenario handleView called with image file
     * @expected setSelectedImageFile and openModal called
     */
    it("should open image viewer modal for image files", () => {
      // Arrange
      const mockSetSelectedImageFile = vi.fn();
      const mockOpenModal = vi.fn();
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        setSelectedImageFile: mockSetSelectedImageFile,
        openModal: mockOpenModal,
      });

      render(<FileManager />);
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      const onView = contentProps.fileListProps.handlers.onView;
      const imageFile = createMockFile(1, { mimeType: "image/png" });

      // Act
      onView(imageFile);

      // Assert
      expect(mockSetSelectedImageFile).toHaveBeenCalledWith(imageFile);
      expect(mockOpenModal).toHaveBeenCalledWith("imageViewer", imageFile);
    });

    /**
     * @description Does nothing for non-image files in view handler
     * @scenario handleView called with non-image file
     * @expected setSelectedImageFile and openModal not called
     */
    it("should not open image viewer for non-image files", () => {
      // Arrange
      const mockSetSelectedImageFile = vi.fn();
      const mockOpenModal = vi.fn();
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        setSelectedImageFile: mockSetSelectedImageFile,
        openModal: mockOpenModal,
      });

      render(<FileManager />);
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      const onView = contentProps.fileListProps.handlers.onView;
      const nonImageFile = createMockFile(1, { mimeType: "application/pdf" });

      // Act
      onView(nonImageFile);

      // Assert
      expect(mockSetSelectedImageFile).not.toHaveBeenCalled();
      expect(mockOpenModal).not.toHaveBeenCalled();
    });

    /**
     * @description Opens corresponding modal for each action handler
     * @scenario onPublicLink, onRename, onEditComment, onDelete called
     * @expected openModal called with correct modal type and file
     */
    it("should open correct modal when action handlers are called", () => {
      // Arrange
      const mockOpenModal = vi.fn();
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        openModal: mockOpenModal,
      });

      render(<FileManager />);
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      const handlers = contentProps.fileListProps.handlers;
      const testFile = createMockFile(1);

      // Act & Assert for each handler
      handlers.onPublicLink(testFile);
      expect(mockOpenModal).toHaveBeenCalledWith("link", testFile);
      mockOpenModal.mockClear();

      handlers.onRename(testFile);
      expect(mockOpenModal).toHaveBeenCalledWith("rename", testFile);
      mockOpenModal.mockClear();

      handlers.onEditComment(testFile);
      expect(mockOpenModal).toHaveBeenCalledWith("comment", testFile);
      mockOpenModal.mockClear();

      handlers.onDelete(testFile);
      expect(mockOpenModal).toHaveBeenCalledWith("delete", testFile);
    });
  });

  // ---------------------------------------------------------------------------
  // MODALS RENDERING
  // ---------------------------------------------------------------------------

  describe("modals rendering", () => {
    /**
     * @description Renders all modals when corresponding flags are true
     * @scenario modalOpen.delete, rename, comment, link, imageViewer all true
     * @expected All modal components are present
     */
    it("should render delete modal when modalOpen.delete is true", () => {
      // Arrange
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: {
          delete: true,
          rename: false,
          comment: false,
          link: false,
          imageViewer: false,
        },
        selectedFile: createMockFile(1),
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(screen.getByTestId("delete-file-modal")).toBeInTheDocument();
    });

    it("should render rename modal when modalOpen.rename is true", () => {
      // Arrange
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: {
          delete: false,
          rename: true,
          comment: false,
          link: false,
          imageViewer: false,
        },
        selectedFile: createMockFile(1),
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(screen.getByTestId("rename-file-modal")).toBeInTheDocument();
    });

    it("should render comment modal when modalOpen.comment is true", () => {
      // Arrange
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: {
          delete: false,
          rename: false,
          comment: true,
          link: false,
          imageViewer: false,
        },
        selectedFile: createMockFile(1),
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(screen.getByTestId("edit-comment-modal")).toBeInTheDocument();
    });

    it("should render link modal when modalOpen.link is true", () => {
      // Arrange
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: {
          delete: false,
          rename: false,
          comment: false,
          link: true,
          imageViewer: false,
        },
        selectedFile: createMockFile(1),
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(screen.getByTestId("public-link-modal")).toBeInTheDocument();
    });

    it("should render image viewer modal when modalOpen.imageViewer is true", () => {
      // Arrange
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: {
          delete: false,
          rename: false,
          comment: false,
          link: false,
          imageViewer: true,
        },
        selectedImageFile: createMockFile(1),
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(screen.getByTestId("image-viewer-modal")).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // EFFECTS
  // ---------------------------------------------------------------------------

  describe("effects", () => {
    /**
     * @description Updates selectedFile when file in list has newer public link data
     * @scenario modalOpen.link true, selectedFile exists, files array contains updated file with different public link status
     * @expected updateSelectedFile called with updated file
     */
    it("should update selectedFile when public link status changes in files list", () => {
      // Arrange
      const mockUpdateSelectedFile = vi.fn();
      const initialFile = createMockFile(1, {
        hasPublicLink: false,
        publicLinkUrl: null,
      });
      const updatedFile = createMockFile(1, {
        hasPublicLink: true,
        publicLinkUrl: "https://example.com",
      });
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: { ...defaultModalsMock.modalOpen, link: true },
        selectedFile: initialFile,
        updateSelectedFile: mockUpdateSelectedFile,
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        files: [updatedFile],
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(mockUpdateSelectedFile).toHaveBeenCalledWith(updatedFile);
    });

    /**
     * @description Does not update selectedFile when no difference in public link data
     * @scenario selectedFile has same public link status as file in list
     * @expected updateSelectedFile not called
     */
    it("should not update selectedFile when public link data unchanged", () => {
      // Arrange
      const mockUpdateSelectedFile = vi.fn();
      const file = createMockFile(1, {
        hasPublicLink: false,
        publicLinkUrl: null,
      });
      mockUseFileManagerModals.mockReturnValue({
        ...defaultModalsMock,
        modalOpen: { ...defaultModalsMock.modalOpen, link: true },
        selectedFile: file,
        updateSelectedFile: mockUpdateSelectedFile,
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        files: [file],
      });

      // Act
      render(<FileManager />);

      // Assert
      expect(mockUpdateSelectedFile).not.toHaveBeenCalled();
    });

    /**
     * @description Resets pagination and invalidates storage cache when upload queue completes
     * @scenario isUploadQueueCompleted becomes true
     * @expected resetPagination called, invalidateTags called with ['UserStorage'], window.scrollTo called
     */
    it("should reset pagination and invalidate storage on upload completion", () => {
      // Arrange
      const mockResetPagination = vi.fn();
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        resetPagination: mockResetPagination,
      });
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsQueueCompleted) return true;
        return undefined;
      });
      const scrollToSpy = vi
        .spyOn(window, "scrollTo")
        .mockImplementation(() => {});

      // Act
      render(<FileManager />);

      // Assert
      expect(mockResetPagination).toHaveBeenCalled();
      expect(mockUserApiInvalidateTags).toHaveBeenCalledWith(["UserStorage"]);
      expect(scrollToSpy).toHaveBeenCalledWith({ top: 0, behavior: "smooth" });

      scrollToSpy.mockRestore();
    });
  });

  // ---------------------------------------------------------------------------
  // DATA PREPARATION FOR FILE LIST
  // ---------------------------------------------------------------------------

  describe("data preparation for FileList", () => {
    /**
     * @description Passes loading state and skeleton renderer when isLoading true
     * @scenario isLoading=true
     * @expected fileListProps.states.isLoading true, renders.renderLoading returns ListSkeleton
     */
    it("should set isLoading true and provide skeleton renderer", () => {
      // Arrange
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        isLoading: true,
        files: [],
      });

      // Act
      render(<FileManager />);

      // Assert
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      expect(contentProps.fileListProps.states.isLoading).toBe(true);
      expect(contentProps.fileListProps.renders.renderLoading()).toEqual(
        <ListSkeleton />,
      );
    });

    /**
     * @description Passes error message when error exists
     * @scenario error = new Error('Network error')
     * @expected states.error = 'Network error'
     */
    it("should pass error message to file list", () => {
      // Arrange
      const error = new Error("Network error");
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        error,
      });

      // Act
      render(<FileManager />);

      // Assert
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      expect(contentProps.fileListProps.states.error).toBe("Network error");
    });

    /**
     * @description Sets emptyMessage and hideEmptyState based on dropzone visibility
     * @scenario isDropzoneVisible true
     * @expected states.emptyMessage set, hideEmptyState true
     */
    it("should hide empty state when dropzone is visible", () => {
      // Arrange
      mockUseFileSearch.mockReturnValue({
        searchTerm: "",
        setSearchTerm: vi.fn(),
        debouncedSearchTerm: "",
      });
      mockUseFileManagerPagination.mockReturnValue({
        ...defaultPaginationMock,
        currentPageFilesCount: 0,
        error: null,
        isLoading: false,
        isFetching: false,
        isDataReady: true,
      });

      // Act
      render(<FileManager isAdmin={false} />);

      // Assert
      const contentProps = mockFileManagerContent.mock.calls[0][0];
      expect(contentProps.fileListProps.states.emptyMessage).toBe(
        "Нет загруженных файлов",
      );
      expect(contentProps.fileListProps.states.hideEmptyState).toBe(true);
    });
  });
});
