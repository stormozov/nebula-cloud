import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { useMediaQuery } from "@/shared/hooks";

import { useUserManager } from "../lib/useUserManager";
import { UserManagementWidget } from "./UserManagementWidget";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../lib/useUserManager");
vi.mock("@/shared/hooks", () => ({
  useMediaQuery: vi.fn(),
}));

vi.mock("@/features/admin", () => ({
  UserDetailsModal: vi.fn(() => (
    <div data-testid="user-details-modal">UserDetailsModal mock</div>
  )),
  UserList: vi.fn(({ users, onSelectUser }) => (
    <div data-testid="user-list">
      {users.map((user: { id: number; username: string }) => (
        <button
          key={user.id}
          type="button"
          onClick={() => onSelectUser(user.id)}
        >
          {user.username}
        </button>
      ))}
    </div>
  )),
  UserSearchInput: vi.fn(({ inputProps }) => (
    <input
      data-testid="user-search-input"
      value={inputProps.value}
      placeholder={inputProps.placeholder}
      onChange={(e) => inputProps.onChange(e.target.value)}
      type="text"
    />
  )),
}));

vi.mock("@/shared/ui", () => ({
  Badge: vi.fn(({ children }) => <span data-testid="badge">{children}</span>),
  Button: vi.fn(({ children, onClick, loading, disabled }) => (
    <button
      data-testid="load-more-button"
      onClick={onClick}
      disabled={disabled || loading}
      type="button"
    >
      {loading ? "Loading..." : children}
    </button>
  )),
  ControlledInput: vi.fn(({ value, onChange, placeholder }) => (
    <input
      data-testid="controlled-input"
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      type="text"
    />
  )),
  Heading: vi.fn(({ children }) => <h2>{children}</h2>),
  ModalConfirm: vi.fn(({ isOpen, title, children, onConfirm, onCancel }) =>
    isOpen ? (
      <div data-testid="modal-confirm">
        <h3>{title}</h3>
        <div>{children}</div>
        <button type="button" onClick={onConfirm}>
          Confirm
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    ) : null,
  ),
  ListSkeleton: vi.fn(() => <div data-testid="list-skeleton">Loading...</div>),
  useModalConfirm: vi.fn(),
}));

const mockUseUserManager = useUserManager as Mock;
const mockUseMediaQuery = useMediaQuery as Mock;

// =============================================================================
// TESTS
// =============================================================================

describe("UserManagementWidget", () => {
  const defaultMockReturn = {
    usersList: {
      items: [],
      totalCount: 0,
      hasMore: false,
      states: { isLoading: false, error: null, emptyMessage: "" },
      renders: {},
    },
    selected: { userId: null, setUserId: vi.fn() },
    pagination: { isLoadMoreLoading: false, loadMore: vi.fn() },
    search: { term: "", setTerm: vi.fn(), debouncedTerm: "" },
    confirmModal: {
      isOpen: false,
      title: "",
      message: "",
      requestConfirm: null,
      handleConfirm: vi.fn(),
      handleCancel: vi.fn(),
    },
    userDetailsModal: {
      userId: null,
      allUserIds: [],
      hasPaginationMore: false,
      isConfirmOpen: false,
      onLoadMore: vi.fn(),
      onNavigate: vi.fn(),
      requestConfirm: null,
      onClose: vi.fn(),
      onUserDeleted: vi.fn(),
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseUserManager.mockReturnValue(defaultMockReturn);
    mockUseMediaQuery.mockReturnValue(false); // не мобильный по умолчанию
  });

  describe("rendering", () => {
    /**
     * @description Renders header with title and user count badge
     * @scenario Users list has totalCount = 5
     * @expected Heading displays "Управление пользователями" and Badge shows "5 пользователей"
     */
    it("should display heading and badge with correct total count", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        usersList: { ...defaultMockReturn.usersList, totalCount: 5 },
      });

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.getByText("Управление пользователями")).toBeInTheDocument();
      expect(screen.getByTestId("badge")).toHaveTextContent("5 пользователей");
    });

    /**
     * @description Renders UserSearchInput on desktop (non-mobile)
     * @scenario useMediaQuery returns false (width > 600px)
     * @expected UserSearchInput component is present, ControlledInput is absent
     */
    it("should render UserSearchInput when not mobile", () => {
      // Arrange
      mockUseMediaQuery.mockReturnValue(false);

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.getByTestId("user-search-input")).toBeInTheDocument();
      expect(screen.queryByTestId("controlled-input")).not.toBeInTheDocument();
    });

    /**
     * @description Renders ControlledInput on mobile (max-width 600px)
     * @scenario useMediaQuery returns true
     * @expected ControlledInput is present, UserSearchInput is absent
     */
    it("should render ControlledInput when on mobile", () => {
      // Arrange
      mockUseMediaQuery.mockReturnValue(true);

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.getByTestId("controlled-input")).toBeInTheDocument();
      expect(screen.queryByTestId("user-search-input")).not.toBeInTheDocument();
    });

    /**
     * @description Renders UserList with users and passes onSelectUser handler
     * @scenario usersList.items contains two users with ids 1 and 2
     * @expected Two buttons rendered, clicking calls selected.setUserId
     */
    it("should render UserList with users and call setUserId on selection", async () => {
      // Arrange
      const setUserId = vi.fn();
      const users = [
        { id: 1, username: "john_doe" },
        { id: 2, username: "jane_doe" },
      ];
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        usersList: { ...defaultMockReturn.usersList, items: users },
        selected: { userId: null, setUserId },
      });

      // Act
      render(<UserManagementWidget />);
      const userButtons = screen.getAllByRole("button", {
        name: /john_doe|jane_doe/,
      });

      // Assert
      expect(userButtons).toHaveLength(2);
      await userEvent.click(userButtons[0]);
      expect(setUserId).toHaveBeenCalledWith(1);
    });

    /**
     * @description Does not render "Load more" button when users list is empty
     * @scenario usersList.items is empty, hasMore is true
     * @expected Load more button not present
     */
    it("should not render load more button when no users", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        usersList: { ...defaultMockReturn.usersList, items: [], hasMore: true },
      });

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.queryByTestId("load-more-button")).not.toBeInTheDocument();
    });

    /**
     * @description Renders load more button when users exist and hasMore is true
     * @scenario usersList.items has at least one user, hasMore = true
     * @expected Load more button visible and enabled
     */
    it("should render load more button when users exist and hasMore is true", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        usersList: {
          ...defaultMockReturn.usersList,
          items: [{ id: 1, username: "test" }],
          hasMore: true,
        },
      });

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.getByTestId("load-more-button")).toBeInTheDocument();
      expect(screen.getByTestId("load-more-button")).not.toBeDisabled();
    });

    /**
     * @description Renders UserDetailsModal when selected.userId is not null
     * @scenario selected.userId = 123
     * @expected UserDetailsModal component appears with modalProps
     */
    it("should render UserDetailsModal when a user is selected", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        selected: { userId: 123, setUserId: vi.fn() },
        userDetailsModal: {
          ...defaultMockReturn.userDetailsModal,
          userId: 123,
        },
      });

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.getByTestId("user-details-modal")).toBeInTheDocument();
    });

    /**
     * @description Does not render UserDetailsModal when selected.userId is null
     * @scenario selected.userId = null
     * @expected UserDetailsModal not present
     */
    it("should not render UserDetailsModal when no user selected", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        selected: { userId: null, setUserId: vi.fn() },
      });

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(
        screen.queryByTestId("user-details-modal"),
      ).not.toBeInTheDocument();
    });

    /**
     * @description Renders ModalConfirm when confirmModal.isOpen is true
     * @scenario confirmModal.isOpen = true, title = "Delete user", message = "Are you sure?"
     * @expected ModalConfirm displays title and message
     */
    it("should render ModalConfirm with correct title and message when open", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        confirmModal: {
          ...defaultMockReturn.confirmModal,
          isOpen: true,
          title: "Delete user",
          message: "Are you sure?",
        },
      });

      // Act
      render(<UserManagementWidget />);

      // Assert
      expect(screen.getByTestId("modal-confirm")).toBeInTheDocument();
      expect(screen.getByText("Delete user")).toBeInTheDocument();
      expect(screen.getByText("Are you sure?")).toBeInTheDocument();
    });
  });

  describe("interactions", () => {
    /**
     * @description Calls search.setTerm when typing into search input (desktop)
     * @scenario User types "john" into UserSearchInput using fireEvent.change
     * @expected search.setTerm is called once with "john"
     */
    it("should call search.setTerm when typing in UserSearchInput on desktop", () => {
      // Arrange
      const setTerm = vi.fn();
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        search: { ...defaultMockReturn.search, term: "", setTerm },
      });
      mockUseMediaQuery.mockReturnValue(false);

      // Act
      render(<UserManagementWidget />);
      const searchInput = screen.getByTestId("user-search-input");
      fireEvent.change(searchInput, { target: { value: "john" } });

      // Assert
      expect(setTerm).toHaveBeenCalledTimes(1);
      expect(setTerm).toHaveBeenCalledWith("john");
    });

    /**
     * @description Calls search.setTerm when typing into ControlledInput on mobile
     * @scenario User types "jane" into ControlledInput using fireEvent.change
     * @expected search.setTerm is called once with "jane"
     */
    it("should call search.setTerm when typing in ControlledInput on mobile", () => {
      // Arrange
      const setTerm = vi.fn();
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        search: { ...defaultMockReturn.search, term: "", setTerm },
      });
      mockUseMediaQuery.mockReturnValue(true);

      // Act
      render(<UserManagementWidget />);
      const searchInput = screen.getByTestId("controlled-input");
      fireEvent.change(searchInput, { target: { value: "jane" } });

      // Assert
      expect(setTerm).toHaveBeenCalledTimes(1);
      expect(setTerm).toHaveBeenCalledWith("jane");
    });

    /**
     * @description Calls pagination.loadMore when clicking "Load more" button
     * @scenario Users exist, hasMore true, click button
     * @expected pagination.loadMore is called with false
     */
    it("should call pagination.loadMore when clicking load more button", async () => {
      // Arrange
      const loadMore = vi.fn();
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        usersList: {
          ...defaultMockReturn.usersList,
          items: [{ id: 1, username: "test" }],
          hasMore: true,
        },
        pagination: { isLoadMoreLoading: false, loadMore },
      });

      // Act
      render(<UserManagementWidget />);
      const loadButton = screen.getByTestId("load-more-button");
      await userEvent.click(loadButton);

      // Assert
      expect(loadMore).toHaveBeenCalledTimes(1);
      expect(loadMore).toHaveBeenCalledWith(false);
    });

    /**
     * @description Disables load more button while loading
     * @scenario pagination.isLoadMoreLoading = true
     * @expected Button is disabled
     */
    it("should disable load more button when loading", () => {
      // Arrange
      mockUseUserManager.mockReturnValue({
        ...defaultMockReturn,
        usersList: {
          ...defaultMockReturn.usersList,
          items: [{ id: 1, username: "test" }],
          hasMore: true,
        },
        pagination: { isLoadMoreLoading: true, loadMore: vi.fn() },
      });

      // Act
      render(<UserManagementWidget />);
      const loadButton = screen.getByTestId("load-more-button");

      // Assert
      expect(loadButton).toBeDisabled();
    });
  });
});
