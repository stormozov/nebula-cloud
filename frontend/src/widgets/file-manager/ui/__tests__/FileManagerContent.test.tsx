import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FileList } from "@/features/file/file-list";

import { FileManagerContent } from "../FileManagerContent";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/features/file/file-list", () => ({
  FileList: vi.fn(() => <div data-testid="file-list" />),
}));

vi.mock("@/shared/ui", () => ({
  Button: vi.fn(({ children, onClick, loading, disabled, icon }) => (
    <button
      type="button"
      data-testid="load-more-button"
      data-loading={loading}
      data-disabled={disabled}
      data-icon-name={icon?.name}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  )),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("FileManagerContent", () => {
  const mockLoadMore = vi.fn();
  const mockFileListProps = {
    files: [],
    onFileSelect: vi.fn(),
    isLoading: false,
    handlers: {}
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when hasNextPage is true", () => {
    const defaultProps = {
      hasNextPage: true,
      isFetching: false,
      fileListProps: mockFileListProps,
      loadMore: mockLoadMore,
    };

    /**
     * @description Renders FileList and load more button when more pages available
     * @scenario hasNextPage = true, isFetching = false
     * @expected FileList is rendered, button with text "Загрузить ещё" is present
     */
    it("should render FileList and load more button", () => {
      // Arrange
      // Act
      render(<FileManagerContent {...defaultProps} />);

      // Assert
      expect(screen.getByTestId("file-list")).toBeInTheDocument();
      expect(screen.getByTestId("load-more-button")).toBeInTheDocument();
      expect(screen.getByTestId("load-more-button")).toHaveTextContent(
        "Загрузить ещё",
      );
    });

    /**
     * @description Passes fileListProps correctly to FileList component
     * @scenario hasNextPage = true
     * @expected FileList is called with all fileListProps
     */
    it("should pass fileListProps to FileList", () => {
      // Arrange
      // Act
      render(<FileManagerContent {...defaultProps} />);

      // Assert
      expect(FileList).toHaveBeenCalledTimes(1);
      const callArgs = (FileList as Mock).mock.calls[0][0];
      expect(callArgs).toEqual(mockFileListProps);
    });

    /**
     * @description Button receives correct props when not fetching
     * @scenario hasNextPage = true, isFetching = false
     * @expected Button receives loading=false, disabled=false, icon.name="retry"
     */
    it("should pass loading=false and disabled=false to button when isFetching is false", () => {
      // Arrange
      // Act
      render(<FileManagerContent {...defaultProps} />);

      // Assert
      const button = screen.getByTestId("load-more-button");
      expect(button).toHaveAttribute("data-loading", "false");
      expect(button).toHaveAttribute("data-disabled", "false");
      expect(button).toHaveAttribute("data-icon-name", "retry");
    });

    /**
     * @description Button receives loading=true and disabled=true when isFetching is true
     * @scenario hasNextPage = true, isFetching = true
     * @expected Button receives loading=true, disabled=true
     */
    it("should pass loading=true and disabled=true to button when isFetching is true", () => {
      // Arrange
      const props = { ...defaultProps, isFetching: true };

      // Act
      render(<FileManagerContent {...props} />);

      // Assert
      const button = screen.getByTestId("load-more-button");
      expect(button).toHaveAttribute("data-loading", "true");
      expect(button).toHaveAttribute("data-disabled", "true");
    });

    /**
     * @description Calls loadMore when load more button is clicked
     * @scenario hasNextPage = true, button is clicked
     * @expected loadMore function is called exactly once
     */
    it("should call loadMore when load more button is clicked", async () => {
      // Arrange
      const user = userEvent.setup();
      render(<FileManagerContent {...defaultProps} />);

      // Act
      await user.click(screen.getByTestId("load-more-button"));

      // Assert
      expect(mockLoadMore).toHaveBeenCalledTimes(1);
    });
  });

  describe("when hasNextPage is false", () => {
    const defaultProps = {
      hasNextPage: false,
      isFetching: false,
      fileListProps: mockFileListProps,
      loadMore: mockLoadMore,
    };

    /**
     * @description Does not render load more button when no more pages
     * @scenario hasNextPage = false
     * @expected Only FileList is rendered, button is absent
     */
    it("should render only FileList without load more button", () => {
      // Arrange
      // Act
      render(<FileManagerContent {...defaultProps} />);

      // Assert
      expect(screen.getByTestId("file-list")).toBeInTheDocument();
      expect(screen.queryByTestId("load-more-button")).not.toBeInTheDocument();
    });

    /**
     * @description loadMore is not called automatically when no button
     * @scenario hasNextPage = false
     * @expected loadMore function is never called (no button to trigger)
     */
    it("should not call loadMore when hasNextPage is false", () => {
      // Arrange
      // Act
      render(<FileManagerContent {...defaultProps} />);

      // Assert
      expect(mockLoadMore).not.toHaveBeenCalled();
    });
  });
});
