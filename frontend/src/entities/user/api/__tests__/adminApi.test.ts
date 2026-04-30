/* eslint-disable @typescript-eslint/no-explicit-any */
/** biome-ignore-all lint/suspicious/noExplicitAny: <for tests> */

import { configureStore } from "@reduxjs/toolkit";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PaginatedResponse } from "@/shared/types/api";

import type { IUserListResponse } from "../../model/types";

// =============================================================================
// MOCK SETUP
// =============================================================================

const baseQueryMock = vi.fn();
vi.mock("@/shared/api", () => ({
  baseQueryWithAuthErrorHandling: baseQueryMock,
}));

const camelToSnakeMock = vi.fn((data: Record<string, unknown>) => ({
  ...data,
}));
vi.mock("@/shared/utils", () => ({
  camelToSnake: camelToSnakeMock,
}));

const { adminApi } = await import("../adminApi");

// =============================================================================
// TEST DATA FACTORIES
// =============================================================================

function createMockUserListResponseItem(
  overrides: Partial<IUserListResponse> = {},
): IUserListResponse {
  return {
    id: 1,
    username: "testuser",
    email: "test@example.com",
    isStaff: false,
    isActive: true,
    ...overrides,
  };
}

function createMockPaginatedResponse(
  overrides: Partial<PaginatedResponse<IUserListResponse>> = {},
): PaginatedResponse<IUserListResponse> {
  return {
    count: 2,
    next: null,
    previous: null,
    results: [
      createMockUserListResponseItem({ id: 1 }),
      createMockUserListResponseItem({ id: 2 }),
    ],
    ...overrides,
  };
}

function createTestStore() {
  return configureStore({
    reducer: {
      [adminApi.reducerPath]: adminApi.reducer,
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware().concat(adminApi.middleware),
  });
}

// =============================================================================
// TEST SUITE
// =============================================================================

describe("adminApi", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    baseQueryMock.mockImplementation(() => ({ data: null }));
  });

  // ---------------------------------------------------------------------------
  // getUsers endpoint
  // ---------------------------------------------------------------------------

  describe("getUsers endpoint", () => {
    const endpoint = adminApi.endpoints.getUsers;

    describe("query construction", () => {
      /**
       * @description should build URL without query params when called with undefined
       * @scenario getUsers query initiated with undefined argument
       * @expected baseQuery called with first argument '/admin/users/'
       */
      it("should build URL without query params when called with undefined", async () => {
        // Arrange
        const store = createTestStore();

        // Act
        store.dispatch(endpoint.initiate(undefined));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledTimes(1);
        expect(baseQueryMock).toHaveBeenCalledWith(
          "/admin/users/",
          expect.any(Object),
          undefined,
        );
      });

      /**
       * @description should build URL with page query param when page provided
       * @scenario getUsers query initiated with { page: 2 }
       * @expected first argument is '/admin/users/?page=2'
       */
      it("should build URL with page query param when page is provided", async () => {
        // Arrange
        const store = createTestStore();

        // Act
        store.dispatch(endpoint.initiate({ page: 2 }));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledWith(
          "/admin/users/?page=2",
          expect.any(Object),
          undefined,
        );
      });

      /**
       * @description should build URL with search param when search provided
       * @scenario getUsers query initiated with { search: 'john' }
       * @expected first argument is '/admin/users/?search=john'
       */
      it("should build URL with search query param when search is provided", async () => {
        // Arrange
        const store = createTestStore();

        // Act
        store.dispatch(endpoint.initiate({ search: "john" }));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledWith(
          "/admin/users/?search=john",
          expect.any(Object),
          undefined,
        );
      });

      /**
       * @description should build URL with page and search when both provided
       * @scenario getUsers query initiated with { page: 3, search: 'admin' }
       * @expected first argument is '/admin/users/?page=3&search=admin'
       */
      it("should build URL with both page and search params when both are provided", async () => {
        // Arrange
        const store = createTestStore();

        // Act
        store.dispatch(endpoint.initiate({ page: 3, search: "admin" }));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledWith(
          "/admin/users/?page=3&search=admin",
          expect.any(Object),
          undefined,
        );
      });
    });

    describe("serializeQueryArgs", () => {
      /**
       * @description should set queryCacheKey based on search parameter
       * @scenario getUsers query initiated with search 'test'
       * @expected API argument contains queryCacheKey 'getUsers-test'
       */
      it("should set queryCacheKey to endpointName-search when search exists", async () => {
        // Arrange
        const store = createTestStore();

        // Act
        store.dispatch(endpoint.initiate({ search: "test" }));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({ queryCacheKey: "getUsers-test" }),
          undefined,
        );
      });

      /**
       * @description should set queryCacheKey to endpointName-empty when no search
       * @scenario getUsers query initiated without arguments
       * @expected API argument contains queryCacheKey 'getUsers-'
       */
      it("should set queryCacheKey to endpointName-empty when no search", async () => {
        // Arrange
        const store = createTestStore();

        // Act
        store.dispatch(endpoint.initiate(undefined));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({ queryCacheKey: "getUsers-" }),
          undefined,
        );
      });
    });

    describe("merge strategy", () => {
      /**
       * @description should cache initial data for page 1
       * @scenario first fetch of page 1
       * @expected cache contains the returned data
       */
      it("should cache initial data for page 1", async () => {
        // Arrange
        const store = createTestStore();
        const page1Data = createMockPaginatedResponse({
          results: [createMockUserListResponseItem({ id: 10 })],
        });
        baseQueryMock.mockResolvedValueOnce({ data: page1Data });

        // Act
        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 10));

        // Assert
        const state = store.getState() as Record<string, any>;
        const cachedData =
          state[adminApi.reducerPath]?.queries?.["getUsers-"]?.data;
        expect(cachedData).toBeDefined();
        expect(cachedData.results).toHaveLength(1);
        expect(cachedData.results[0].id).toBe(10);
      });

      /**
       * @description should merge new users when fetching different page
       * @scenario fetch page 1 then page 2
       * @expected cache appends new results without duplicates
       */
      it("should append new unique users when page > 1", async () => {
        // Arrange
        const store = createTestStore();
        const user1 = createMockUserListResponseItem({ id: 1 });
        const user2 = createMockUserListResponseItem({ id: 2 });
        const user3 = createMockUserListResponseItem({ id: 3 });
        const page1Data = createMockPaginatedResponse({
          results: [user1, user2],
        });
        const page2Data = createMockPaginatedResponse({
          results: [user2, user3],
          next: "next-page",
        });

        baseQueryMock
          .mockResolvedValueOnce({ data: page1Data })
          .mockResolvedValueOnce({ data: page2Data });

        // Act
        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 10));
        store.dispatch(endpoint.initiate({ page: 2 }));
        await new Promise((r) => setTimeout(r, 10));

        // Assert
        const state = store.getState() as Record<string, any>;
        const cached =
          state[adminApi.reducerPath]?.queries?.["getUsers-"]?.data;
        expect(cached).toBeDefined();
        expect(cached.results).toHaveLength(3);
        expect(cached.results.map((u: { id: number }) => u.id)).toEqual([
          1, 2, 3,
        ]);
        expect(cached.next).toBe("next-page");
      });
    });

    describe("forceRefetch", () => {
      /**
       * @description should refetch when page changes
       * @scenario fetch page 1, then fetch page 2
       * @expected baseQuery is called twice
       */
      it("should refetch when page changes", async () => {
        // Arrange
        const store = createTestStore();
        baseQueryMock.mockResolvedValue({
          data: createMockPaginatedResponse(),
        });

        // Act
        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 0));
        store.dispatch(endpoint.initiate({ page: 2 }));
        await new Promise((r) => setTimeout(r, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledTimes(2);
      });

      /**
       * @description should not refetch when page unchanged
       * @scenario fetch page 1 twice
       * @expected baseQuery called only once
       */
      it("should not refetch when page is the same", async () => {
        // Arrange
        const store = createTestStore();
        baseQueryMock.mockResolvedValue({
          data: createMockPaginatedResponse(),
        });

        // Act
        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 0));
        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledTimes(1);
      });
    });

    describe("providesTags", () => {
      /**
       * @description should refetch getUsers after deleteUser invalidates LIST tag
       * @scenario deleteUser mutation dispatched, then getUsers subscribed
       * @expected getUsers refetched
       */
      it("should refetch getUsers after deleteUser invalidates LIST tag", async () => {
        // Arrange
        const store = createTestStore();
        baseQueryMock.mockResolvedValueOnce({
          data: createMockPaginatedResponse(),
        }); // initial getUsers
        baseQueryMock.mockResolvedValueOnce({ data: { detail: "ok" } }); // deleteUser
        baseQueryMock.mockResolvedValueOnce({
          data: createMockPaginatedResponse(),
        }); // refetched getUsers

        // Act
        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 0));
        expect(baseQueryMock).toHaveBeenCalledTimes(1);

        store.dispatch(adminApi.endpoints.deleteUser.initiate(1) as any);
        await new Promise((r) => setTimeout(r, 0));

        store.dispatch(endpoint.initiate({ page: 1 }));
        await new Promise((r) => setTimeout(r, 0));

        // Assert
        expect(baseQueryMock).toHaveBeenCalledTimes(3);
      });
    });
  });

  // ---------------------------------------------------------------------------
  // getUser endpoint
  // ---------------------------------------------------------------------------

  describe("getUser endpoint", () => {
    /**
     * @description should fetch user details by ID with correct URL
     * @scenario getUser query initiated with id 42
     * @expected baseQuery first argument '/admin/users/42/'
     */
    it("should fetch user details by ID with correct URL", async () => {
      // Arrange
      const store = createTestStore();

      // Act
      store.dispatch(adminApi.endpoints.getUser.initiate(42));
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      expect(baseQueryMock).toHaveBeenCalledWith(
        "/admin/users/42/",
        expect.any(Object),
        undefined,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // updateUser endpoint
  // ---------------------------------------------------------------------------

  describe("updateUser endpoint", () => {
    /**
     * @description should send PATCH request with camelToSnake transformed data
     * @scenario updateUser mutation dispatched with id 1 and data
     * @expected baseQuery called with object containing method PATCH, url, and body from camelToSnake
     */
    it("should send PATCH request with camelToSnake transformed data", async () => {
      // Arrange
      const store = createTestStore();
      const userData = { firstName: "John" } as any;
      camelToSnakeMock.mockImplementation((data) => ({
        ...data,
        converted: true,
      }));

      // Act
      store.dispatch(
        adminApi.endpoints.updateUser.initiate({
          id: 1,
          data: userData,
        }) as any,
      );
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      expect(camelToSnakeMock).toHaveBeenCalledWith(userData);
      const callArgs = baseQueryMock.mock.calls[0];
      expect(callArgs[0]).toMatchObject({
        url: "/admin/users/1/",
        method: "PATCH",
        body: { firstName: "John", converted: true },
      });
    });
  });

  // —--------------------------------------------------------------------------
  // deleteUser endpoint
  // —--------------------------------------------------------------------------

  describe("deleteUser endpoint", () => {
    /**
     * @description should send DELETE request with correct URL
     * @scenario deleteUser mutation dispatched with id 10
     * @expected baseQuery called with object containing method DELETE and url
     */
    it("should send DELETE request with correct URL", async () => {
      // Arrange
      const store = createTestStore();

      // Act
      store.dispatch(adminApi.endpoints.deleteUser.initiate(10) as any);
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      const callArgs = baseQueryMock.mock.calls[0];
      expect(callArgs[0]).toMatchObject({
        url: "/admin/users/10/",
        method: "DELETE",
      });
    });
  });

  // ---------------------------------------------------------------------------
  // resetPassword endpoint
  // ---------------------------------------------------------------------------

  describe("resetPassword endpoint", () => {
    /**
     * @description should send POST request with new password transformed to snake_case
     * @scenario resetPassword mutation dispatched with id 7 and password
     * @expected baseQuery called with object containing url, method POST, body from camelToSnake
     */
    it("should send POST request with new password transformed to snake_case", async () => {
      // Arrange
      const store = createTestStore();
      camelToSnakeMock.mockImplementation((data) => ({
        new_password: (data as any).newPassword,
      }));

      // Act
      store.dispatch(
        adminApi.endpoints.resetPassword.initiate({
          id: 7,
          newPassword: "pwd123",
        }) as any,
      );
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      expect(camelToSnakeMock).toHaveBeenCalledWith({ newPassword: "pwd123" });
      const callArgs = baseQueryMock.mock.calls[0];
      expect(callArgs[0]).toMatchObject({
        url: "/admin/users/7/password/",
        method: "POST",
        body: { new_password: "pwd123" },
      });
    });
  });

  // —--------------------------------------------------------------------------
  // toggleAdmin endpoint
  // —--------------------------------------------------------------------------

  describe("toggleAdmin endpoint", () => {
    /**
     * @description should send POST request with isStaff flag transformed to snake_case
     * @scenario toggleAdmin mutation dispatched with id 3 and isStaff true
     * @expected baseQuery called with url, method POST, body from camelToSnake
     */
    it("should send POST request with isStaff flag transformed to snake_case", async () => {
      // Arrange
      const store = createTestStore();
      camelToSnakeMock.mockImplementation((data) => ({
        is_staff: (data as any).isStaff,
      }));

      // Act
      store.dispatch(
        adminApi.endpoints.toggleAdmin.initiate({
          id: 3,
          isStaff: true,
        }) as any,
      );
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      expect(camelToSnakeMock).toHaveBeenCalledWith({ isStaff: true });
      const callArgs = baseQueryMock.mock.calls[0];
      expect(callArgs[0]).toMatchObject({
        url: "/admin/users/3/toggle-admin/",
        method: "POST",
        body: { is_staff: true },
      });
    });
  });

  // ---------------------------------------------------------------------------
  // getStorageStats endpoint
  // ---------------------------------------------------------------------------

  describe("getStorageStats endpoint", () => {
    /**
     * @description should fetch storage stats with correct URL by user ID
     * @scenario getStorageStats query initiated with user id 99
     * @expected baseQuery first argument is '/admin/users/99/storage-stats/'
     */
    it("should fetch storage stats with correct URL by user ID", async () => {
      // Arrange
      const store = createTestStore();

      // Act
      store.dispatch(adminApi.endpoints.getStorageStats.initiate(99));
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      expect(baseQueryMock).toHaveBeenCalledWith(
        "/admin/users/99/storage-stats/",
        expect.any(Object),
        undefined,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // exportUserData endpoint
  // ---------------------------------------------------------------------------

  describe("exportUserData endpoint", () => {
    /**
     * @description should send GET export request with correct URL
     * @scenario exportUserData mutation dispatched with user id 8
     * @expected baseQuery called with object containing method GET and url
     */
    it("should send GET export request with correct URL", async () => {
      // Arrange
      const store = createTestStore();

      // Act
      store.dispatch(adminApi.endpoints.exportUserData.initiate(8) as any);
      await new Promise((r) => setTimeout(r, 0));

      // Assert
      const callArgs = baseQueryMock.mock.calls[0];
      expect(callArgs[0]).toMatchObject({
        url: "/admin/users/8/export/",
        method: "GET",
      });
    });
  });
});
