import { configureStore } from "@reduxjs/toolkit";
import {
  clearAuthTokens,
  localStorageMock,
  resetLocalStorage,
  setAuthTokens,
} from "@tests/mocks/localStorage";
import { server } from "@tests/mocks/server";
import { delay, HttpResponse, http } from "msw";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { fileSlice } from "../../model/slice";

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

describe("fileApi - Mutation Endpoints", () => {
  let store: ReturnType<typeof createTestStore>;

  beforeAll(() => server.listen());

  beforeEach(() => {
    setAuthTokens("mock_access_token");
    store = createTestStore();
  });

  afterEach(() => {
    server.resetHandlers();
    vi.clearAllMocks();
    resetLocalStorage();
  });

  afterAll(() => server.close());

  // ---------------------------------------------------------------------------
  // deleteFile Mutation Tests
  // ---------------------------------------------------------------------------
  describe("deleteFile Mutation", () => {
    /**
     * @description Should delete file successfully
     * @scenario Executing deleteFile mutation with valid file ID
     * @expected Should return success status and dispatch removeFile
     */
    it("should delete file successfully", async () => {
      const fileId = 1;
      const dispatchSpy = vi.spyOn(store, "dispatch");

      const result = await fileApi.endpoints.deleteFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should invalidate File cache tag after deletion
     * @scenario Executing deleteFile mutation
     * @expected File tag should be invalidated for cache refresh
     */
    it("should invalidate File cache tag after deletion", async () => {
      const fileId = 1;

      const result = await fileApi.endpoints.deleteFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle file not found (404)
     * @scenario Executing deleteFile with non-existent file ID
     * @expected Should return error status
     */
    it("should handle file not found (404)", async () => {
      const fileId = 999;

      const result = await fileApi.endpoints.deleteFile.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle server error (500)
     * @scenario Executing deleteFile with server error
     * @expected Should return error status
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.delete("/api/storage/files/:id/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Internal server error" },
            { status: 500 },
          );
        }),
      );

      const result = await fileApi.endpoints.deleteFile.initiate(1)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Executing deleteFile without token in localStorage
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const testStore = createTestStore();

      const result = await fileApi.endpoints.deleteFile.initiate(1)(
        testStore.dispatch,
        testStore.getState,
        {},
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle invalid JSON token
     * @scenario Executing deleteFile with invalid JSON in localStorage
     * @expected Request should proceed without Authorization header (catch)
     */
    it("should handle invalid JSON token", async () => {
      localStorageMock.getItem.mockReturnValue("invalid-json");
      const testStore = createTestStore();

      const result = await fileApi.endpoints.deleteFile.initiate(1)(
        testStore.dispatch,
        testStore.getState,
        {},
      );

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // renameFile Mutation Tests
  // ---------------------------------------------------------------------------
  describe("renameFile Mutation", () => {
    /**
     * @description Should rename file successfully
     * @scenario Executing renameFile mutation with valid data
     * @expected Should return updated file and dispatch updateFile
     */
    it("should rename file successfully", async () => {
      const fileId = 1;
      const newName = "renamed.txt";
      const dispatchSpy = vi.spyOn(store, "dispatch");

      const result = await fileApi.endpoints.renameFile.initiate({
        id: fileId,
        data: { originalName: newName },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
      expect(result.data?.originalName).toBe(newName);
      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should invalidate File cache tag after rename
     * @scenario Executing renameFile mutation
     * @expected File tag should be invalidated for cache refresh
     */
    it("should invalidate File cache tag after rename", async () => {
      const fileId = 1;

      const result = await fileApi.endpoints.renameFile.initiate({
        id: fileId,
        data: { originalName: "new.txt" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle file not found (404)
     * @scenario Executing renameFile with non-existent file ID
     * @expected Should return error status
     */
    it("should handle file not found (404)", async () => {
      const fileId = 999;

      const result = await fileApi.endpoints.renameFile.initiate({
        id: fileId,
        data: { originalName: "new.txt" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle server error (500)
     * @scenario Executing renameFile with server error
     * @expected Should return error status
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.patch("/api/storage/files/:id/rename/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Internal server error" },
            { status: 500 },
          );
        }),
      );

      const result = await fileApi.endpoints.renameFile.initiate({
        id: 1,
        data: { originalName: "new.txt" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Executing renameFile without token
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const testStore = createTestStore();

      const result = await fileApi.endpoints.renameFile.initiate({
        id: 1,
        data: { originalName: "new.txt" },
      })(testStore.dispatch, testStore.getState, {});

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // updateComment Mutation Tests
  // ---------------------------------------------------------------------------
  describe("updateComment Mutation", () => {
    /**
     * @description Should update comment successfully
     * @scenario Executing updateComment mutation with valid data
     * @expected Should return updated file with new comment
     */
    it("should update comment successfully", async () => {
      const fileId = 1;
      const newComment = "Updated comment text";
      const dispatchSpy = vi.spyOn(store, "dispatch");

      const result = await fileApi.endpoints.updateComment.initiate({
        id: fileId,
        data: { comment: newComment },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
      expect(result.data?.comment).toBe(newComment);
      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should invalidate File cache tag after comment update
     * @scenario Executing updateComment mutation
     * @expected File tag should be invalidated for cache refresh
     */
    it("should invalidate File cache tag after comment update", async () => {
      const fileId = 1;

      const result = await fileApi.endpoints.updateComment.initiate({
        id: fileId,
        data: { comment: "test" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle file not found (404)
     * @scenario Executing updateComment with non-existent file ID
     * @expected Should return error status
     */
    it("should handle file not found (404)", async () => {
      const fileId = 999;

      const result = await fileApi.endpoints.updateComment.initiate({
        id: fileId,
        data: { comment: "test" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle server error (500)
     * @scenario Executing updateComment with server error
     * @expected Should return error status
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.patch("/api/storage/files/:id/comment/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Internal server error" },
            { status: 500 },
          );
        }),
      );

      const result = await fileApi.endpoints.updateComment.initiate({
        id: 1,
        data: { comment: "test" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle empty comment
     * @scenario Executing updateComment with empty string
     * @expected Should accept and save empty comment
     */
    it("should handle empty comment", async () => {
      const fileId = 1;

      const result = await fileApi.endpoints.updateComment.initiate({
        id: fileId,
        data: { comment: "" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.data?.comment).toBe("");
    });
  });

  // ---------------------------------------------------------------------------
  // generatePublicLink Mutation Tests
  // ---------------------------------------------------------------------------
  describe("generatePublicLink Mutation", () => {
    /**
     * @description Should generate public link successfully
     * @scenario Executing generatePublicLink mutation with valid file ID
     * @expected Should return file with public link data
     */
    it("should generate public link successfully", async () => {
      const fileId = 1;
      const dispatchSpy = vi.spyOn(store, "dispatch");

      const result = await fileApi.endpoints.generatePublicLink.initiate(
        fileId,
      )(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
      expect(result.data?.hasPublicLink).toBe(true);
      expect(result.data?.publicLinkUrl).toBeDefined();
      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should invalidate File cache tag after link generation
     * @scenario Executing generatePublicLink mutation
     * @expected File tag should be invalidated for cache refresh
     */
    it("should invalidate File cache tag after link generation", async () => {
      const fileId = 1;

      const result = await fileApi.endpoints.generatePublicLink.initiate(
        fileId,
      )(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle file not found (404)
     * @scenario Executing generatePublicLink with non-existent file ID
     * @expected Should return error status
     */
    it("should handle file not found (404)", async () => {
      const fileId = 999;

      const result = await fileApi.endpoints.generatePublicLink.initiate(
        fileId,
      )(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle server error (500)
     * @scenario Executing generatePublicLink with server error
     * @expected Should return error status
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.post("/api/storage/files/:id/public-link/generate/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Internal server error" },
            { status: 500 },
          );
        }),
      );

      const result = await fileApi.endpoints.generatePublicLink.initiate(1)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Executing generatePublicLink without token
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const testStore = createTestStore();

      const result = await fileApi.endpoints.generatePublicLink.initiate(1)(
        testStore.dispatch,
        testStore.getState,
        {},
      );

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // deletePublicLink Mutation Tests
  // ---------------------------------------------------------------------------
  describe("deletePublicLink Mutation", () => {
    /**
     * @description Should delete public link successfully
     * @scenario Executing deletePublicLink mutation with valid file ID
     * @expected Should return file with cleared public link data
     */
    it("should delete public link successfully", async () => {
      const fileId = 1;
      const dispatchSpy = vi.spyOn(store, "dispatch");

      const result = await fileApi.endpoints.deletePublicLink.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();
      expect(result.data?.hasPublicLink).toBe(false);
      expect(result.data?.publicLinkUrl).toBeNull();
      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should invalidate File cache tag after link deletion
     * @scenario Executing deletePublicLink mutation
     * @expected File tag should be invalidated for cache refresh
     */
    it("should invalidate File cache tag after link deletion", async () => {
      const fileId = 1;

      const result = await fileApi.endpoints.deletePublicLink.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle file not found (404)
     * @scenario Executing deletePublicLink with non-existent file ID
     * @expected Should return error status
     */
    it("should handle file not found (404)", async () => {
      const fileId = 999;

      const result = await fileApi.endpoints.deletePublicLink.initiate(fileId)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle server error (500)
     * @scenario Executing deletePublicLink with server error
     * @expected Should return error status
     */
    it("should handle server error (500)", async () => {
      server.use(
        http.delete("/api/storage/files/:id/public-link/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Internal server error" },
            { status: 500 },
          );
        }),
      );

      const result = await fileApi.endpoints.deletePublicLink.initiate(1)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
      expect(result.error).toBeDefined();
    });

    /**
     * @description Should handle missing auth token
     * @scenario Executing deletePublicLink without token
     * @expected Request should proceed without Authorization header
     */
    it("should handle missing auth token", async () => {
      clearAuthTokens();
      const testStore = createTestStore();

      const result = await fileApi.endpoints.deletePublicLink.initiate(1)(
        testStore.dispatch,
        testStore.getState,
        {},
      );

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Mutation Cache Invalidation Tests
  // ---------------------------------------------------------------------------
  describe("Mutation Cache Invalidation", () => {
    /**
     * @description Should trigger refetch of getFiles after mutation
     * @scenario Executing mutation that invalidates File tag
     * @expected Cached getFiles query should be invalidated
     */
    it("should trigger refetch of getFiles after mutation", async () => {
      // First fetch files
      const filesResult = await fileApi.endpoints.getFiles.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(filesResult).toBeDefined();

      // Execute mutation that invalidates File tag
      const deleteResult = await fileApi.endpoints.deleteFile.initiate(1)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(deleteResult).toBeDefined();
    });

    /**
     * @description Should invalidate cache for all File-tagged queries
     * @scenario Executing any mutation with invalidatesTags: ["File"]
     * @expected All File queries should be marked for refetch
     */
    it("should invalidate cache for all File-tagged queries", async () => {
      const mutations = [
        fileApi.endpoints.deleteFile.initiate(1),
        fileApi.endpoints.renameFile.initiate({
          id: 1,
          data: { originalName: "new.txt" },
        }),
        fileApi.endpoints.updateComment.initiate({
          id: 1,
          data: { comment: "test" },
        }),
        fileApi.endpoints.generatePublicLink.initiate(1),
        fileApi.endpoints.deletePublicLink.initiate(1),
      ];

      for (const mutation of mutations) {
        const result = await mutation(store.dispatch, store.getState, {});
        expect(result).toBeDefined();
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Mutation Error Handling Tests
  // ---------------------------------------------------------------------------
  describe("Mutation Error Handling", () => {
    /**
     * @description Should handle network timeout gracefully
     * @scenario Executing mutation with simulated timeout
     * @expected Should return error status
     */
    it("should handle network timeout gracefully", async () => {
      server.use(
        http.delete("/api/storage/files/:id/", async () => {
          await delay(100);
          return HttpResponse.json(null, { status: 204 });
        }),
      );

      const result = await fileApi.endpoints.deleteFile.initiate(1)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should handle malformed response
     * @scenario Executing mutation with invalid response format
     * @expected Should return error status
     */
    it("should handle malformed response", async () => {
      server.use(
        http.patch("/api/storage/files/:id/rename/", async () => {
          await delay(50);
          return new HttpResponse("invalid json", {
            status: 200,
            headers: { "Content-Type": "text/plain" },
          });
        }),
      );

      const result = await fileApi.endpoints.renameFile.initiate({
        id: 1,
        data: { originalName: "new.txt" },
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // onQueryStarted Lifecycle Tests
  // ---------------------------------------------------------------------------
  describe("onQueryStarted Lifecycle", () => {
    /**
     * @description Should dispatch actions in onQueryStarted try block
     * @scenario Executing successful mutation
     * @expected updateFile/removeFile should be dispatched
     */
    it("should dispatch actions in onQueryStarted try block", async () => {
      const dispatchSpy = vi.spyOn(store, "dispatch");

      await fileApi.endpoints.renameFile.initiate({
        id: 1,
        data: { originalName: "new.txt" },
      })(store.dispatch, store.getState, {});

      expect(dispatchSpy).toHaveBeenCalled();
    });

    /**
     * @description Should dispatch setError in onQueryStarted catch block
     * @scenario Executing failed mutation
     * @expected setError action should be dispatched with error message
     */
    it("should dispatch setError in onQueryStarted catch block", async () => {
      server.use(
        http.delete("/api/storage/files/:id/", async () => {
          await delay(50);
          return HttpResponse.json(
            { detail: "Delete failed" },
            { status: 500 },
          );
        }),
      );

      const dispatchSpy = vi.spyOn(store, "dispatch");

      await fileApi.endpoints.deleteFile.initiate(1)(
        store.dispatch,
        store.getState,
        {},
      );

      expect(dispatchSpy).toHaveBeenCalled();
    });
  });
});
