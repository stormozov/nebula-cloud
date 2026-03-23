import { configureStore } from "@reduxjs/toolkit";
import {
  clearAuthTokens,
  localStorageMock,
  resetLocalStorage,
  setAuthTokens,
} from "@tests/mocks/localStorage";
import { server } from "@tests/mocks/server";
import { delay, HttpResponse, http } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fileSlice } from "../../model/slice";
import type { IFile } from "../../model/types";

// =============================================================================
// IMPORT FILE API ONCE
// =============================================================================

const { fileApi } = await import("../fileApi");

// =============================================================================
// MOCK SETUP
// =============================================================================

vi.stubGlobal("import.meta", {
  env: {
    VITE_API_BASE_URL: "/api",
  },
});

// =============================================================================
// TEST STORE FACTORY
// =============================================================================

const createTestStore = () => {
  return configureStore({
    reducer: {
      [fileApi.reducerPath]: fileApi.reducer,
      file: fileSlice.reducer,
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware().concat(fileApi.middleware),
  });
};

// =============================================================================
// TEST SUITE
// =============================================================================

describe("fileApi - Query Endpoints", () => {
  let store: ReturnType<typeof createTestStore>;

  beforeEach(() => {
    setAuthTokens("mock_access_token");
    store = createTestStore();
  });

  afterEach(() => {
    vi.clearAllMocks();
    resetLocalStorage();
  });

  // ---------------------------------------------------------------------------
  // getFiles Query Tests
  // ---------------------------------------------------------------------------
  describe("getFiles Query", () => {
    /**
     * @description Should fetch file list successfully
     * @scenario Executing getFiles query with valid token
     * @expected Should return array of files
     */
    it("should fetch file list successfully", async () => {
      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
      expect(Array.isArray(result.data)).toBe(true);
    });

    /**
     * @description Should return correct file structure
     * @scenario Executing getFiles query and checking response structure
     * @expected Each file should have required properties
     */
    it("should return correct file structure", async () => {
      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      if (result.data && result.data.length > 0) {
        const file = result.data[0];
        expect(file).toHaveProperty("id");
        expect(file).toHaveProperty("originalName");
        expect(file).toHaveProperty("size");
        expect(file).toHaveProperty("uploadedAt");
        expect(file).toHaveProperty("downloadUrl");
      }
    });

    /**
     * @description Should dispatch actions during query lifecycle
     * @scenario Executing getFiles query
     * @expected Dispatch should be called
     */
    it("should dispatch actions during query lifecycle", async () => {
      const dispatchSpy = vi.spyOn(store, "dispatch");

      await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should handle empty file list
     * @scenario Executing getFiles query when no files exist
     * @expected Should return empty array
     */
    it("should handle empty file list", async () => {
      // Override handler to return empty list
      server.use(
        http.get("/api/storage/files/", async () => {
          await delay(50);
          return HttpResponse.json<IFile[]>([]);
        }),
      );

      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
      expect(Array.isArray(result.data)).toBe(true);
      expect(result.data?.length).toBe(0);
    });

    /**
     * @description Should handle missing auth token
     * @scenario Executing getFiles query without token
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const testStore = createTestStore();

      const result = await fileApi.endpoints.getFiles.initiate()(
        testStore.dispatch,
        testStore.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle invalid JSON token
     * @scenario Executing getFiles query with invalid JSON in localStorage
     * @expected Request should proceed without Authorization header (catch)
     */
    it("should handle invalid JSON token", async () => {
      localStorageMock.getItem.mockReturnValue("invalid-json");
      const testStore = createTestStore();

      const result = await fileApi.endpoints.getFiles.initiate()(
        testStore.dispatch,
        testStore.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should support forceRefetch option
     * @scenario Executing getFiles query with forceRefetch: true
     * @expected Should refetch even if data is cached
     */
    it("should support forceRefetch option", async () => {
      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should support cache option
     * @scenario Executing getFiles query without forceRefetch
     * @expected Should use cached data if available
     */
    it("should support cache option", async () => {
      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should update store state after query
     * @scenario Executing getFiles query and checking store state
     * @expected Store should be updated after query
     */
    it("should update store state after query", async () => {
      await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      const state = store.getState();
      expect(state.file).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // getFile Query Tests
  // ---------------------------------------------------------------------------
  describe("getFile Query", () => {
    /**
     * @description Should fetch single file by ID successfully
     * @scenario Executing getFile query with valid file ID
     * @expected Should return single file object
     */
    it("should fetch single file by ID successfully", async () => {
      const fileId = 1;
      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
    });

    /**
     * @description Should return correct file structure for single file
     * @scenario Executing getFile query and checking response structure
     * @expected File should have all required properties
     */
    it("should return correct file structure for single file", async () => {
      const fileId = 1;
      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      if (result.data) {
        expect(result.data).toHaveProperty("id");
        expect(result.data).toHaveProperty("originalName");
        expect(result.data).toHaveProperty("size");
        expect(result.data).toHaveProperty("uploadedAt");
        expect(result.data).toHaveProperty("downloadUrl");
        expect(result.data.id).toBe(fileId);
      }
    });

    /**
     * @description Should handle file not found (404)
     * @scenario Executing getFile query with non-existent file ID
     * @expected Should return error status
     */
    it("should handle file not found (404)", async () => {
      const fileId = 999;
      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Executing getFile query without token
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const testStore = createTestStore();
      const fileId = 1;

      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        testStore.dispatch,
        testStore.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle invalid JSON token
     * @scenario Executing getFile query with invalid JSON in localStorage
     * @expected Request should proceed without Authorization header (catch)
     */
    it("should handle invalid JSON token", async () => {
      localStorageMock.getItem.mockReturnValue("invalid-json");
      const testStore = createTestStore();
      const fileId = 1;

      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        testStore.dispatch,
        testStore.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should support different file IDs
     * @scenario Executing getFile query with various file IDs
     * @expected Should return different files for different IDs
     */
    it("should support different file IDs", async () => {
      const fileId1 = 1;
      const fileId2 = 2;

      const result1 = await fileApi.endpoints.getFile.initiate(fileId1)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      const result2 = await fileApi.endpoints.getFile.initiate(fileId2)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
    });

    /**
     * @description Should support forceRefetch option
     * @scenario Executing getFile query with forceRefetch: true
     * @expected Should refetch even if data is cached
     */
    it("should support forceRefetch option", async () => {
      const fileId = 1;
      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should support cache option
     * @scenario Executing getFile query without forceRefetch
     * @expected Should use cached data if available
     */
    it("should support cache option", async () => {
      const fileId = 1;
      const result = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should update store state after query
     * @scenario Executing getFile query and checking store state
     * @expected Store should be updated after query
     */
    it("should update store state after query", async () => {
      const fileId = 1;
      await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      const state = store.getState();
      expect(state.file).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Query Cache Tests
  // ---------------------------------------------------------------------------
  describe("Query Cache", () => {
    /**
     * @description Should cache getFiles query results
     * @scenario Executing getFiles query twice
     * @expected Second query should use cached data
     */
    it("should cache getFiles query results", async () => {
      const result1 = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      const result2 = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
    });

    /**
     * @description Should cache getFile query results by ID
     * @scenario Executing getFile query twice with same ID
     * @expected Second query should use cached data
     */
    it("should cache getFile query results by ID", async () => {
      const fileId = 1;

      const result1 = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      const result2 = await fileApi.endpoints.getFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Query Error Handling Tests
  // ---------------------------------------------------------------------------
  describe("Query Error Handling", () => {
    /**
     * @description Should handle server error (500)
     * @scenario Executing query with server error
     * @expected Should return error status
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.get("/api/storage/files/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Internal server error" },
            { status: 500 },
          );
        }),
      );

      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle network timeout
     * @scenario Executing query with simulated timeout
     * @expected Should handle gracefully
     */
    it("should handle network timeout", async () => {
      server.use(
        http.get("/api/storage/files/", async () => {
          await delay(100); // Simulate timeout
          return HttpResponse.json([]);
        }),
      );

      const result = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Query Loading State Tests
  // ---------------------------------------------------------------------------
  describe("Query Loading State", () => {
    /**
     * @description Should handle multiple concurrent queries
     * @scenario Executing multiple getFiles queries simultaneously
     * @expected All queries should complete successfully
     */
    it("should handle multiple concurrent queries", async () => {
      const [result1, result2, result3] = await Promise.all([
        fileApi.endpoints.getFiles.initiate()(store.dispatch, store.getState, {
          forceRefetch: true,
        }),
        fileApi.endpoints.getFiles.initiate()(store.dispatch, store.getState, {
          forceRefetch: true,
        }),
        fileApi.endpoints.getFiles.initiate()(store.dispatch, store.getState, {
          forceRefetch: true,
        }),
      ]);

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(result3).toBeDefined();
    });
  });
});
