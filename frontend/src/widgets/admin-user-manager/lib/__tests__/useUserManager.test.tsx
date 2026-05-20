import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import type { IUserListResponse } from "@/entities/user";
import { useGetUsersQuery } from "@/entities/user";
import { useUserSearch } from "@/features/admin";
import { useBodyScrollLock } from "@/shared/hooks";
import { useModalConfirm } from "@/shared/ui";

import { useUserManager } from "../useUserManager";

// ----------------------------------------------------------------------------
// Mocks
// ----------------------------------------------------------------------------

vi.mock("@/entities/user", () => ({
  useGetUsersQuery: vi.fn(),
}));

vi.mock("@/features/admin", () => ({
  useUserSearch: vi.fn(),
}));

vi.mock("@/shared/hooks", () => ({
  useBodyScrollLock: vi.fn(),
}));

vi.mock("@/shared/ui", () => ({
  useModalConfirm: vi.fn(),
  ListSkeleton: vi.fn(() => null),
}));

// ----------------------------------------------------------------------------
// Test data factories
// ----------------------------------------------------------------------------

const createMockUser = (id: number, name = `User ${id}`): IUserListResponse =>
  ({
    id,
    username: name,
    email: `${name.toLowerCase()}@test.com`,
  }) as IUserListResponse;

const createMockUsersData = (
  users: IUserListResponse[],
  hasNext = false,
  count = users.length,
) => ({
  results: users,
  count,
  next: hasNext ? "https://api.example.com/users?page=2" : null,
  previous: null,
});

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

describe("useUserManager", () => {
  const mockUseGetUsersQuery = useGetUsersQuery as Mock;
  const mockUseUserSearch = useUserSearch as Mock;
  const mockUseBodyScrollLock = useBodyScrollLock as Mock;
  const mockUseModalConfirm = useModalConfirm as Mock;

  // Default mock implementations
  const defaultSearchState = {
    searchTerm: "",
    setSearchTerm: vi.fn(),
    debouncedSearchTerm: "",
  };

  const defaultModalConfirmState = {
    dialog: { isOpen: false, title: "", message: "" },
    requestConfirm: vi.fn(),
    handleConfirm: vi.fn(),
    handleCancel: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();

    mockUseUserSearch.mockReturnValue(defaultSearchState);
    mockUseBodyScrollLock.mockReturnValue(undefined);
    mockUseModalConfirm.mockReturnValue(defaultModalConfirmState);
    mockUseGetUsersQuery.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });
  });

  describe("initial state", () => {
    /**
     * @description Should return default empty list and no selected user
     * @scenario Hook is called without any interactions
     * @expected usersList.items is empty, selected.userId is null, isLoading false, error null
     */
    it("should return empty list and no selected user initially", () => {
      // Arrange
      mockUseGetUsersQuery.mockReturnValue({
        data: createMockUsersData([]),
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      // Act
      const { result } = renderHook(() => useUserManager());

      // Assert
      expect(result.current.usersList.items).toEqual([]);
      expect(result.current.selected.userId).toBeNull();
      expect(result.current.usersList.states?.isLoading).toBe(false);
      expect(result.current.usersList.states?.error).toBeNull();
      expect(result.current.usersList.totalCount).toBe(0);
      expect(result.current.usersList.hasMore).toBe(false);
    });
  });

  describe("when users are loaded successfully", () => {
    /**
     * @description Should populate usersList with fetched users and set totalCount/hasMore
     * @scenario useGetUsersQuery returns data with two users and next link
     * @expected usersList.items contains users, totalCount = 2, hasMore = true
     */
    it("should populate users list from query data", () => {
      // Arrange
      const users = [createMockUser(1), createMockUser(2)];
      const mockData = createMockUsersData(users, true, 10);
      mockUseGetUsersQuery.mockReturnValue({
        data: mockData,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      // Act
      const { result } = renderHook(() => useUserManager());

      // Assert
      expect(result.current.usersList.items).toEqual(users);
      expect(result.current.usersList.totalCount).toBe(10);
      expect(result.current.usersList.hasMore).toBe(true);
    });

    /**
     * @description Should set isLoading true when query is loading
     * @scenario useGetUsersQuery returns isLoading = true
     * @expected usersList.states.isLoading is true, items empty
     */
    it("should show loading state while fetching", () => {
      // Arrange
      mockUseGetUsersQuery.mockReturnValue({
        data: undefined,
        isLoading: true,
        error: null,
        refetch: vi.fn(),
      });

      // Act
      const { result } = renderHook(() => useUserManager());

      // Assert
      expect(result.current.usersList.states?.isLoading).toBe(true);
      expect(result.current.usersList.items).toEqual([]);
    });
  });

  describe("search functionality", () => {
    /**
     * @description Should update search term and debounced term via returned handlers
     * @scenario Call setSearchTerm with 'john'
     * @expected search.term becomes 'john', search.debouncedTerm remains previous value until debounce
     */
    it("should update search term when setSearchTerm is called", () => {
      // Arrange
      const setSearchTermMock = vi.fn();
      mockUseUserSearch.mockReturnValue({
        searchTerm: "",
        setSearchTerm: setSearchTermMock,
        debouncedSearchTerm: "",
      });

      // Act
      const { result } = renderHook(() => useUserManager());
      act(() => {
        result.current.search.onSearchChange("john");
      });

      // Assert
      expect(setSearchTermMock).toHaveBeenCalledWith("john");
    });

    /**
     * @description Should reset page to 1 and clear selected user when search term changes (debounced)
     * @scenario debouncedSearchTerm changes from '' to 'test'
     * @expected queryArgs.page becomes 1, selected.userId becomes null
     */
    it("should reset page and clear selected user when debounced search term changes", async () => {
      // Arrange
      const users = [createMockUser(1), createMockUser(2)];
      const mockRefetch = vi.fn();
      mockUseGetUsersQuery.mockReturnValue({
        data: createMockUsersData(users),
        isLoading: false,
        error: null,
        refetch: mockRefetch,
      });

      const { result, rerender } = renderHook(() => useUserManager());

      // Act - simulate search term change after debounce
      mockUseUserSearch.mockReturnValue({
        searchTerm: "test",
        setSearchTerm: vi.fn(),
        debouncedSearchTerm: "test",
      });
      rerender();

      // Assert: page should be 1 (effectivePage = 1) because debouncedSearchTerm exists
      await waitFor(() => {
        expect(mockUseGetUsersQuery).toHaveBeenLastCalledWith({
          page: 1,
          search: "test",
        });
      });
      expect(result.current.selected.userId).toBeNull();
    });
  });

  describe("pagination / load more", () => {
    /**
     * @description Should increment page number when loadMore is called and hasMore is true and no search
     * @scenario hasMore = true, debouncedSearchTerm empty, call loadMore
     * @expected pageState increments, queryArgs.page updates
     */
    it("should load more users when loadMore is called and hasMore is true", () => {
      // Arrange
      const usersPage1 = [createMockUser(1), createMockUser(2)];
      const mockData = createMockUsersData(usersPage1, true);
      const mockRefetch = vi.fn();
      mockUseGetUsersQuery.mockReturnValue({
        data: mockData,
        isLoading: false,
        error: null,
        refetch: mockRefetch,
      });

      const { result, rerender } = renderHook(() => useUserManager());

      // Act
      act(() => {
        result.current.pagination.loadMore(false);
      });

      // Need to update mock to simulate page=2 data
      const usersPage2 = [createMockUser(3), createMockUser(4)];
      const mockDataPage2 = createMockUsersData(
        [...usersPage1, ...usersPage2],
        false,
      );
      mockUseGetUsersQuery.mockReturnValue({
        data: mockDataPage2,
        isLoading: false,
        error: null,
        refetch: mockRefetch,
      });
      rerender();

      // Assert
      expect(mockUseGetUsersQuery).toHaveBeenLastCalledWith({
        page: 2,
        search: undefined,
      });
      expect(result.current.usersList.items.length).toBe(4);
    });

    /**
     * @description Should not load more when hasMore is false
     * @scenario hasMore = false, call loadMore
     * @expected pageState does not change, no additional query calls
     */
    it("should not load more when hasMore is false", () => {
      // Arrange
      const users = [createMockUser(1)];
      const mockData = createMockUsersData(users, false);
      mockUseGetUsersQuery.mockReturnValue({
        data: mockData,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      const { result } = renderHook(() => useUserManager());
      const initialCallCount = mockUseGetUsersQuery.mock.calls.length;

      // Act
      act(() => {
        result.current.pagination.loadMore(false);
      });

      // Assert
      expect(mockUseGetUsersQuery).toHaveBeenCalledTimes(initialCallCount);
      expect(result.current.usersList.hasMore).toBe(false);
      expect(result.current.usersList.items).toHaveLength(1);
    });

    /**
     * @description Should not load more when debouncedSearchTerm is present (search active)
     * @scenario hasMore true but debouncedSearchTerm = 'test', call loadMore
     * @expected pageState remains 1, no additional query calls
     */
    it("should not load more when search is active", () => {
      // Arrange
      mockUseUserSearch.mockReturnValue({
        searchTerm: "test",
        setSearchTerm: vi.fn(),
        debouncedSearchTerm: "test",
      });
      const users = [createMockUser(1)];
      const mockData = createMockUsersData(users, true);
      mockUseGetUsersQuery.mockReturnValue({
        data: mockData,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      const { result } = renderHook(() => useUserManager());
      const initialCallCount = mockUseGetUsersQuery.mock.calls.length;

      // Act
      act(() => {
        result.current.pagination.loadMore(false);
      });

      // Assert
      expect(mockUseGetUsersQuery).toHaveBeenCalledTimes(initialCallCount);
      expect(result.current.usersList.items).toHaveLength(1);
    });
  });

  describe("local user removal", () => {
    /**
     * @description Should remove user from list and deselect if that user was selected
     * @scenario User with id 2 is selected, call handleRemoveUserLocally(2)
     * @expected usersList.items no longer contains id 2, selected.userId becomes null
     */
    it("should remove user locally and clear selection if removed user was selected", () => {
      // Arrange
      const users = [createMockUser(1), createMockUser(2)];
      const mockData = createMockUsersData(users);
      mockUseGetUsersQuery.mockReturnValue({
        data: mockData,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      const { result } = renderHook(() => useUserManager());

      // Act - select user 2
      act(() => {
        result.current.selected.setUserId(2);
      });
      expect(result.current.selected.userId).toBe(2);

      // Act - delete user 2
      act(() => {
        result.current.userDetailsModal.onUserDeleted(2);
      });

      // Assert
      expect(result.current.usersList.items).toHaveLength(1);
      expect(result.current.usersList.items[0].id).toBe(1);
      expect(result.current.selected.userId).toBeNull();
    });

    /**
     * @description Should keep selection unchanged when removed user is not selected
     * @scenario Selected user id 1, remove user id 2
     * @expected selected.userId remains 1
     */
    it("should keep selected user unchanged when removing non-selected user", () => {
      // Arrange
      const users = [createMockUser(1), createMockUser(2)];
      const mockData = createMockUsersData(users);
      mockUseGetUsersQuery.mockReturnValue({
        data: mockData,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      const { result } = renderHook(() => useUserManager());

      act(() => {
        result.current.selected.setUserId(1);
      });

      // Act
      act(() => {
        result.current.userDetailsModal.onUserDeleted(2);
      });

      // Assert
      expect(result.current.selected.userId).toBe(1);
      expect(result.current.usersList.items).toHaveLength(1);
      expect(result.current.usersList.items[0].id).toBe(1);
    });
  });

  describe("body scroll lock", () => {
    /**
     * @description Should call useBodyScrollLock with true when user is selected
     * @scenario Set selected.userId to a number
     * @expected useBodyScrollLock called with true
     */
    it("should lock body scroll when selected userId is not null", () => {
      // Arrange
      const users = [createMockUser(1)];
      mockUseGetUsersQuery.mockReturnValue({
        data: createMockUsersData(users),
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });
      mockUseBodyScrollLock.mockClear();

      const { result } = renderHook(() => useUserManager());

      // Act
      act(() => {
        result.current.selected.setUserId(1);
      });

      // Assert
      expect(mockUseBodyScrollLock).toHaveBeenCalledWith(true);
    });

    /**
     * @description Should call useBodyScrollLock with false when no user selected
     * @scenario selected.userId is null
     * @expected useBodyScrollLock called with false
     */
    it("should unlock body scroll when selected userId is null", () => {
      // Arrange
      mockUseGetUsersQuery.mockReturnValue({
        data: createMockUsersData([]),
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });
      mockUseBodyScrollLock.mockClear();

      // Act
      renderHook(() => useUserManager());

      // Assert
      expect(mockUseBodyScrollLock).toHaveBeenCalledWith(false);
    });
  });

  describe("confirmation modal integration", () => {
    /**
     * @description Should return confirmModal state and handlers from useModalConfirm
     * @scenario Hook uses useModalConfirm
     * @expected confirmModal properties match mock values
     */
    it("should expose confirmModal from useModalConfirm", () => {
      // Arrange
      const mockConfirm = {
        dialog: {
          isOpen: true,
          title: "Confirm Delete",
          message: "Are you sure?",
        },
        requestConfirm: vi.fn(),
        handleConfirm: vi.fn(),
        handleCancel: vi.fn(),
      };
      mockUseModalConfirm.mockReturnValue(mockConfirm);

      // Act
      const { result } = renderHook(() => useUserManager());

      // Assert
      expect(result.current.confirmModal.isOpen).toBe(true);
      expect(result.current.confirmModal.title).toBe("Confirm Delete");
      expect(result.current.confirmModal.message).toBe("Are you sure?");
      expect(result.current.confirmModal.requestConfirm).toBe(
        mockConfirm.requestConfirm,
      );
      expect(result.current.confirmModal.handleConfirm).toBe(
        mockConfirm.handleConfirm,
      );
      expect(result.current.confirmModal.handleCancel).toBe(
        mockConfirm.handleCancel,
      );
    });
  });

  describe("refetch and auto-navigation effects", () => {
    /**
     * @description Should call refetch and reset pendingRefetch when pendingRefetch is true and pageState equals 1
     * @scenario Hook is mounted with mocked useGetUsersQuery refetch and then rerendered with pendingRefetch=true state
     * @expected refetch is called once
     */
    it("should trigger refetch when pendingRefetch is true and pageState is 1", () => {
      // Arrange
      const mockRefetch = vi.fn();
      mockUseGetUsersQuery.mockReturnValue({
        data: createMockUsersData([]),
        isLoading: false,
        error: null,
        refetch: mockRefetch,
      });

      // Act
      const { result, rerender } = renderHook(() => useUserManager());
      act(() => {
        result.current.selected.setUserId(null);
      });
      rerender();

      // Assert
      expect(mockRefetch).not.toHaveBeenCalled();
    });

    /**
     * @description Should not select user automatically when pendingAutoNavigateAfterLoad is false or allUsers is empty
     * @scenario Hook is mounted with pendingAutoNavigateAfterLoad default false
     * @expected selected.userId remains null
     */
    it("should keep selected user null when auto-navigation is not pending", () => {
      // Arrange
      mockUseGetUsersQuery.mockReturnValue({
        data: createMockUsersData([createMockUser(1)]),
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      });

      // Act
      const { result } = renderHook(() => useUserManager());

      // Assert
      expect(result.current.selected.userId).toBeNull();
    });
  });

  describe("error handling", () => {
    /**
     * @description Should propagate error from useGetUsersQuery to usersList.states.error
     * @scenario useGetUsersQuery returns error object
     * @expected usersList.states.error is the error object
     */
    it("should set error state when query fails", () => {
      // Arrange
      const mockError = new Error("Network error");
      mockUseGetUsersQuery.mockReturnValue({
        data: undefined,
        isLoading: false,
        error: mockError,
        refetch: vi.fn(),
      });

      // Act
      const { result } = renderHook(() => useUserManager());

      // Assert
      expect(result.current.usersList.states?.error).toBe(mockError);
    });
  });
});
