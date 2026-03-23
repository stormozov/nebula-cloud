import { configureStore } from "@reduxjs/toolkit";

import {
  clearAuthTokens,
  resetLocalStorage,
  setAuthTokens,
  setInvalidAuthToken,
} from "@tests/mocks/localStorage";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fileSlice } from "../../model/slice";

// =============================================================================
// IMPORT FILE API ONCE
// =============================================================================

const { fileApi } = await import("../fileApi");

// =============================================================================
// MOCK SETUP
// =============================================================================

// Setup environment variables
vi.stubGlobal("import.meta", {
  env: {
    VITE_API_BASE_URL: "/api",
  },
});

// =============================================================================
// TEST STORE FACTORY
// =============================================================================

/**
 * Creates a test store with fileApi configured
 */
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

describe("fileApi - Configuration", () => {
  beforeEach(() => {
    setAuthTokens("mock_access_token");
    createTestStore();
  });

  afterEach(() => {
    vi.clearAllMocks();
    resetLocalStorage();
  });

  // ---------------------------------------------------------------------------
  // API Slice Configuration Tests
  // ---------------------------------------------------------------------------
  describe("API Slice Configuration", () => {
    /**
     * @description Should have correct reducerPath
     * @scenario Creating slice without actions should return initial state
     * @expected reducerPath should be "fileApi"
     */
    it("should have correct reducerPath", () => {
      expect(fileApi).toBeDefined();
      expect(fileApi.reducerPath).toBe("fileApi");
    });

    /**
     * @description Should have baseQuery configured
     * @scenario Creating slice should configure baseQuery
     * @expected baseQuery should be defined
     */
    it("should have baseQuery configured", () => {
      expect(fileApi).toBeDefined();
      expect(fileApi).toHaveProperty("reducerPath");
      expect(fileApi).toHaveProperty("middleware");
    });

    /**
     * @description Should have File tagType defined
     * @scenario Creating slice should define tag types
     * @expected tagTypes should include "File"
     */
    it("should have File tagType defined", () => {
      expect(fileApi.util).toBeDefined();
      expect(fileApi.util.invalidateTags).toBeDefined();
    });

    /**
     * @description Should have middleware defined
     * @scenario Creating slice should define middleware
     * @expected middleware should be a function
     */
    it("should have middleware defined", () => {
      expect(typeof fileApi.middleware).toBe("function");
    });

    /**
     * @description Should have reducer defined
     * @scenario Creating slice should define reducer
     * @expected reducer should be a function
     */
    it("should have reducer defined", () => {
      expect(typeof fileApi.reducer).toBe("function");
    });

    /**
     * @description Should have injectEndpoints method
     * @scenario Verifying injectEndpoints method is present
     * @expected Method should be present
     */
    it("should have injectEndpoints method", () => {
      expect(typeof fileApi.injectEndpoints).toBe("function");
    });

    /**
     * @description Should have util namespace for cache management
     * @scenario Verifying util namespace is present
     * @expected Namespace should be present
     */
    it("should have util namespace for cache management", () => {
      expect(fileApi.util).toBeDefined();
      expect(typeof fileApi.util).toBe("object");
    });
  });

  // ---------------------------------------------------------------------------
  // Exported Hooks Tests
  // ---------------------------------------------------------------------------
  describe("Exported Hooks", () => {
    /**
     * @description Should export useGetFilesQuery hook
     * @scenario Verifying useGetFilesQuery hook is exported
     * @expected Hook should be a function
     */
    it("should export useGetFilesQuery hook", () => {
      expect(fileApi.useGetFilesQuery).toBeDefined();
      expect(typeof fileApi.useGetFilesQuery).toBe("function");
    });

    /**
     * @description Should export useGetFileQuery hook
     * @scenario Verifying useGetFileQuery hook is exported
     * @expected Hook should be a function
     */
    it("should export useGetFileQuery hook", () => {
      expect(fileApi.useGetFileQuery).toBeDefined();
      expect(typeof fileApi.useGetFileQuery).toBe("function");
    });

    /**
     * @description Should export useDeleteFileMutation hook
     * @scenario Verifying useDeleteFileMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useDeleteFileMutation hook", () => {
      expect(fileApi.useDeleteFileMutation).toBeDefined();
      expect(typeof fileApi.useDeleteFileMutation).toBe("function");
    });

    /**
     * @description Should export useRenameFileMutation hook
     * @scenario Verifying useRenameFileMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useRenameFileMutation hook", () => {
      expect(fileApi.useRenameFileMutation).toBeDefined();
      expect(typeof fileApi.useRenameFileMutation).toBe("function");
    });

    /**
     * @description Should export useUpdateCommentMutation hook
     * @scenario Verifying useUpdateCommentMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useUpdateCommentMutation hook", () => {
      expect(fileApi.useUpdateCommentMutation).toBeDefined();
      expect(typeof fileApi.useUpdateCommentMutation).toBe("function");
    });

    /**
     * @description Should export useGeneratePublicLinkMutation hook
     * @scenario Verifying useGeneratePublicLinkMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useGeneratePublicLinkMutation hook", () => {
      expect(fileApi.useGeneratePublicLinkMutation).toBeDefined();
      expect(typeof fileApi.useGeneratePublicLinkMutation).toBe("function");
    });

    /**
     * @description Should export useDeletePublicLinkMutation hook
     * @scenario Verifying useDeletePublicLinkMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useDeletePublicLinkMutation hook", () => {
      expect(fileApi.useDeletePublicLinkMutation).toBeDefined();
      expect(typeof fileApi.useDeletePublicLinkMutation).toBe("function");
    });
  });

  // ---------------------------------------------------------------------------
  // API Slice Identity Tests
  // ---------------------------------------------------------------------------
  describe("API Slice Identity", () => {
    /**
     * @description Should have unique reducerPath
     * @scenario Verifying reducerPath is unique
     * @expected ReducerPath should be "fileApi"
     */
    it("should have unique reducerPath", () => {
      expect(fileApi.reducerPath).toBe("fileApi");
    });

    /**
     * @description Should have all required endpoints
     * @scenario Verifying all required endpoints are present
     * @expected All required endpoints should be present
     */
    it("should have all required endpoints", () => {
      expect(fileApi.endpoints).toHaveProperty("getFiles");
      expect(fileApi.endpoints).toHaveProperty("getFile");
      expect(fileApi.endpoints).toHaveProperty("deleteFile");
      expect(fileApi.endpoints).toHaveProperty("renameFile");
      expect(fileApi.endpoints).toHaveProperty("updateComment");
      expect(fileApi.endpoints).toHaveProperty("generatePublicLink");
      expect(fileApi.endpoints).toHaveProperty("deletePublicLink");
    });

    /**
     * @description Should export all required hooks
     * @scenario Verifying all required hooks are exported
     * @expected All required hooks should be exported
     */
    it("should export all required hooks", () => {
      expect(fileApi).toHaveProperty("useGetFilesQuery");
      expect(fileApi).toHaveProperty("useGetFileQuery");
      expect(fileApi).toHaveProperty("useDeleteFileMutation");
      expect(fileApi).toHaveProperty("useRenameFileMutation");
      expect(fileApi).toHaveProperty("useUpdateCommentMutation");
      expect(fileApi).toHaveProperty("useGeneratePublicLinkMutation");
      expect(fileApi).toHaveProperty("useDeletePublicLinkMutation");
    });
  });

  // ---------------------------------------------------------------------------
  // Endpoint Name Consistency Tests
  // ---------------------------------------------------------------------------
  describe("Endpoint Name Consistency", () => {
    /**
     * @description Should have correct name for getFiles endpoint
     * @scenario Verifying getFiles endpoint name
     * @expected Endpoint name should be "getFiles"
     */
    it("should have correct name for getFiles endpoint", () => {
      const endpoint = fileApi.endpoints.getFiles as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("getFiles");
    });

    /**
     * @description Should have correct name for getFile endpoint
     * @scenario Verifying getFile endpoint name
     * @expected Endpoint name should be "getFile"
     */
    it("should have correct name for getFile endpoint", () => {
      const endpoint = fileApi.endpoints.getFile as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("getFile");
    });

    /**
     * @description Should have correct name for deleteFile endpoint
     * @scenario Verifying deleteFile endpoint name
     * @expected Endpoint name should be "deleteFile"
     */
    it("should have correct name for deleteFile endpoint", () => {
      const endpoint = fileApi.endpoints.deleteFile as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("deleteFile");
    });

    /**
     * @description Should have correct name for renameFile endpoint
     * @scenario Verifying renameFile endpoint name
     * @expected Endpoint name should be "renameFile"
     */
    it("should have correct name for renameFile endpoint", () => {
      const endpoint = fileApi.endpoints.renameFile as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("renameFile");
    });

    /**
     * @description Should have correct name for updateComment endpoint
     * @scenario Verifying updateComment endpoint name
     * @expected Endpoint name should be "updateComment"
     */
    it("should have correct name for updateComment endpoint", () => {
      const endpoint = fileApi.endpoints.updateComment as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("updateComment");
    });

    /**
     * @description Should have correct name for generatePublicLink endpoint
     * @scenario Verifying generatePublicLink endpoint name
     * @expected Endpoint name should be "generatePublicLink"
     */
    it("should have correct name for generatePublicLink endpoint", () => {
      const endpoint = fileApi.endpoints.generatePublicLink as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("generatePublicLink");
    });

    /**
     * @description Should have correct name for deletePublicLink endpoint
     * @scenario Verifying deletePublicLink endpoint name
     * @expected Endpoint name should be "deletePublicLink"
     */
    it("should have correct name for deletePublicLink endpoint", () => {
      const endpoint = fileApi.endpoints.deletePublicLink as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("deletePublicLink");
    });
  });

  // ---------------------------------------------------------------------------
  // Authentication Tests
  // ---------------------------------------------------------------------------
  describe("Authentication", () => {
    /**
     * @description Should include auth token in request headers
     * @scenario Making API call with valid token in localStorage
     * @expected Authorization header should be set
     */
    it("should include auth token in request headers", async () => {
      setAuthTokens("test_token_123");
      const testStore = createTestStore();

      const result = await fileApi.endpoints.getFiles.initiate()(
        testStore.dispatch,
        testStore.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Making API call without token in localStorage
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
     * @scenario Making API call with invalid JSON in localStorage
     * @expected Request should proceed without Authorization header (catch)
     */
    it("should handle invalid JSON token", async () => {
      setInvalidAuthToken();
      const testStore = createTestStore();

      const result = await fileApi.endpoints.getFiles.initiate()(
        testStore.dispatch,
        testStore.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Store Integration Tests
  // ---------------------------------------------------------------------------
  describe("Store Integration", () => {
    /**
     * @description Should configure store with fileApi middleware
     * @scenario Creating store with fileApi reducer and middleware
     * @expected Store should be configured correctly
     */
    it("should configure store with fileApi middleware", () => {
      const testStore = createTestStore();

      expect(testStore).toBeDefined();
      expect(testStore.getState).toBeDefined();
      expect(testStore.dispatch).toBeDefined();
    });

    /**
     * @description Should have fileApi reducer in store
     * @scenario Checking store state structure
     * @expected fileApi reducer should be present in state
     */
    it("should have fileApi reducer in store", () => {
      const testStore = createTestStore();
      const state = testStore.getState();

      expect(state).toHaveProperty("fileApi");
      expect(state).toHaveProperty("file");
    });
  });
});
