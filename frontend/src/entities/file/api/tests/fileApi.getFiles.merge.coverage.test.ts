import { configureStore } from "@reduxjs/toolkit";
import { fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import {
  clearAuthTokens,
  resetLocalStorage,
  setAuthTokens,
} from "@tests/mocks/localStorage";
import { server } from "@tests/mocks/server";
import { HttpResponse, http } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { IFile } from "../../model/types";

// =============================================================================
// MOCK SHARED API DEPENDENCIES
// =============================================================================

vi.mock("@/shared/api", () => ({
  baseQueryWithAuthErrorHandling: fetchBaseQuery({ baseUrl: "/api" }),
  extractApiErrorMessage: vi.fn(
    (error: Record<string, unknown>) => (error?.message as string) ?? "Error",
  ),
  fetchWithAuth: vi.fn((url: string, init?: RequestInit) => fetch(url, init)),
  getRefreshedToken: vi.fn(),
  API_BASE_URL: "/api",
}));

const createMockFile = (
  id: number,
  originalName: string,
): IFile => ({
  id,
  originalName,
  comment: null,
  size: 1024,
  sizeFormatted: "1 KB",
  uploadedAt: new Date().toISOString(),
  lastDownloaded: null,
  hasPublicLink: false,
  publicLinkUrl: null,
  downloadUrl: `/api/storage/files/${id}/download/`,
});

const createMockPage = (pageFiles: IFile[], next: string | null) => {
  return {
    results: pageFiles,
    next,
  };
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const createTestStore = () =>
  configureStore({
    reducer: {
      // fileApi reducer will be injected after dynamic import
    },
    middleware: (getDefaultMiddleware) => getDefaultMiddleware(),
  });

// =============================================================================
// TESTS
// =============================================================================

describe("fileApi getFiles merge behavior", () => {
  let fileApi: typeof import("../fileApi").fileApi;
  let store: ReturnType<typeof createTestStore>;

  beforeEach(async () => {
    clearAuthTokens();
    resetLocalStorage();
    setAuthTokens("mock_access_token");

    // Import after mocks are set
    const mod = await import("../fileApi");
    fileApi = mod.fileApi;

    store = configureStore({
      reducer: {
        [fileApi.reducerPath]: fileApi.reducer,
      },
      middleware: (getDefaultMiddleware) =>
        getDefaultMiddleware().concat(fileApi.middleware),
    });

    server.resetHandlers();
  });

  afterEach(() => {
    vi.clearAllMocks();
    resetLocalStorage();
    server.resetHandlers();
  });

  describe("merge callback for page > 1", () => {
    /**
     * @description should append new files and update existing ones by id when merging page > 1
     * @scenario Dispatch getFiles for page=1 then page=2 where page=2 contains an existing id and a new id
     * @expected Cache results should include updated existing item and newly appended item
     */
    it("should append and replace items by id when merging page 2 into page 1 cache", async () => {
      // Arrange
      const page1Files = [createMockFile(1, "file-1-v1.txt"), createMockFile(2, "file-2.txt")];
      const page2Files = [createMockFile(2, "file-2-v2.txt"), createMockFile(3, "file-3.txt")];
      let byId = new Map<number, IFile>();

      server.use(
        http.get("/api/storage/files/", ({ request }) => {
          const url = new URL(request.url);
          const page = url.searchParams.get("page");

          if (page === "1") {
            return HttpResponse.json(createMockPage(page1Files, "next"));
          }

          if (page === "2") {
            return HttpResponse.json(createMockPage(page2Files, null));
          }

          return HttpResponse.json(createMockPage([], null));
        }),
      );

      // Act
      await store.dispatch(fileApi.endpoints.getFiles.initiate({ page: 1 }));
      const mergedResult = await store.dispatch(
        fileApi.endpoints.getFiles.initiate({ page: 2 }),
      );

      // Assert
      const mergedFiles = mergedResult.data?.results;
      expect(mergedFiles).toBeDefined();
      expect(mergedFiles).toHaveLength(3); 

      if (mergedFiles) {
        byId = new Map<number, IFile>(mergedFiles.map((f) => [f.id, f]));
      }

      expect(byId.get(1)?.originalName).toBe("file-1-v1.txt");
      expect(byId.get(2)?.originalName).toBe("file-2-v2.txt");
      expect(byId.get(3)?.originalName).toBe("file-3.txt");
    });

    /**
     * @description should keep page 1 response as-is when merging page=1
     * @scenario Dispatch getFiles for page=1 where merge should return newItems directly
     * @expected Cache should equal the first page results without mutations
     */
    it("should not merge with existing cache when dispatching page 1", async () => {
      // Arrange
      const page1Files = [createMockFile(10, "p1-a.txt"), createMockFile(11, "p1-b.txt")];

      server.use(
        http.get("/api/storage/files/", ({ request }) => {
          const url = new URL(request.url);
          const page = url.searchParams.get("page");

          if (page === "1") {
            return HttpResponse.json(createMockPage(page1Files, null));
          }

          return HttpResponse.json(createMockPage([], null));
        }),
      );

      // Act
      const result = await store.dispatch(
        fileApi.endpoints.getFiles.initiate({ page: 1 }),
      );

      // Assert
      expect(result.data).toBeDefined();
      expect(result.data?.results).toHaveLength(2);
      expect(result.data?.results[0].originalName).toBe("p1-a.txt");
      expect(result.data?.results[1].originalName).toBe("p1-b.txt");
    });
  });
});

