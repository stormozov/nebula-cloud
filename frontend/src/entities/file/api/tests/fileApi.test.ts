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

// =============================================================================
// IMPORT MODULE UNDER TEST
// =============================================================================

const { fileApi, downloadFileFromApi, getImageBlobFromApi } = await import(
  "../fileApi"
);

// =============================================================================
// MOCK SETUP
// =============================================================================

vi.stubGlobal("import.meta", {
  env: {
    VITE_API_BASE_URL: "/api",
  },
});

vi.mock("@/shared/utils", () => ({
  downloadFile: vi.fn(),
}));

import { downloadFile } from "@/shared/utils";

// =============================================================================
// MOCK DATA FACTORIES
// =============================================================================

const createMockFile = (
  id: number,
  originalName: string = "test.txt",
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

const createMockFileList = (): IFile[] => [
  createMockFile(1, "file1.txt"),
  createMockFile(2, "file2.txt"),
];

// =============================================================================
// TEST STORE FACTORY
// =============================================================================

const createTestStore = () =>
  configureStore({
    reducer: {
      [fileApi.reducerPath]: fileApi.reducer,
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware().concat(fileApi.middleware),
  });

// =============================================================================
// TEST SUITE
// =============================================================================

describe("fileApi", () => {
  let store: ReturnType<typeof createTestStore>;

  beforeEach(() => {
    setAuthTokens("mock_access_token");
    store = createTestStore();
  });

  afterEach(() => {
    vi.clearAllMocks();
    resetLocalStorage();
    server.resetHandlers();
  });

  // ---------------------------------------------------------------------------
  // downloadFileFromApi
  // ---------------------------------------------------------------------------

  describe("downloadFileFromApi", () => {
    const fileId = 10;
    const filename = "download.txt";

    beforeEach(() => {
      server.use(
        http.get("/api/storage/files/10/download/", () => {
          return new HttpResponse("binary data", {
            status: 200,
            headers: { "Content-Type": "application/octet-stream" },
          });
        }),
      );
    });

    /**
     * @description should download file and call browser download utility
     * @scenario Calling downloadFileFromApi with valid fileId and filename
     * @expected getImageBlobFromApi is called internally and downloadFile is invoked with the blob
     */
    it("should download file and call browser download utility", async () => {
      // Arrange
      const downloadFileMock = downloadFile as ReturnType<typeof vi.fn>;

      // Act
      await downloadFileFromApi(fileId, filename);

      // Assert
      expect(downloadFileMock).toHaveBeenCalledOnce();
      const blobArg = downloadFileMock.mock.calls[0][0] as Blob;
      expect(blobArg).toBeInstanceOf(Blob);
      expect(downloadFileMock).toHaveBeenCalledWith(blobArg, filename);
    });

    /**
     * @description should silently return when fetch returns 401
     * @scenario Calling downloadFileFromApi but server returns 401
     * @expected No download is triggered and no error is thrown
     */
    it("should silently return when fetch returns 401", async () => {
      // Arrange
      server.use(
        http.get("/api/storage/files/10/download/", () => {
          return new HttpResponse(null, { status: 401 });
        }),
      );
      const downloadFileMock = downloadFile as ReturnType<typeof vi.fn>;

      // Act
      await downloadFileFromApi(fileId, filename);

      // Assert
      expect(downloadFileMock).not.toHaveBeenCalled();
    });

    /**
     * @description should log error when download fails with non-401 status
     * @scenario Server returns 500 during download
     * @expected Console.error is called and downloadFile is not invoked
     */
    it("should log error when download fails with non-401 status", async () => {
      // Arrange
      server.use(
        http.get("/api/storage/files/10/download/", () => {
          return new HttpResponse(null, { status: 500 });
        }),
      );
      const consoleErrorSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const downloadFileMock = downloadFile as ReturnType<typeof vi.fn>;

      // Act
      await downloadFileFromApi(fileId, filename);

      // Assert
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        "Download failed:",
        expect.any(Error),
      );
      expect(downloadFileMock).not.toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  // ---------------------------------------------------------------------------
  // getImageBlobFromApi
  // ---------------------------------------------------------------------------

  describe("getImageBlobFromApi", () => {
    const fileId = 20;

    /**
     * @description should fetch and return blob for given fileId
     * @scenario Calling getImageBlobFromApi with valid fileId
     * @expected Returns a Blob with correct content type
     */
    it("should fetch and return blob for given fileId", async () => {
      // Arrange
      server.use(
        http.get("/api/storage/files/20/download/", () => {
          return new HttpResponse("image data", {
            status: 200,
            headers: { "Content-Type": "image/png" },
          });
        }),
      );

      // Act
      const blob = await getImageBlobFromApi(fileId);

      // Assert
      expect(blob).toBeInstanceOf(Blob);
      expect(blob.type).toBe("image/png");
    });

    /**
     * @description should throw when server returns non-ok status
     * @scenario Server returns 404 for the download endpoint
     * @expected Promise rejects with an error
     */
    it("should throw when server returns non-ok status", async () => {
      // Arrange
      server.use(
        http.get("/api/storage/files/20/download/", () => {
          return new HttpResponse(null, { status: 404 });
        }),
      );

      // Act & Assert
      await expect(getImageBlobFromApi(fileId)).rejects.toThrowError();
    });
  });

  // ---------------------------------------------------------------------------
  // fileApi endpoints
  // ---------------------------------------------------------------------------

  describe("fileApi endpoints", () => {
    // ---------- getFiles ----------
    describe("getFiles", () => {
      /**
       * @description should fetch file list with default parameters
       * @scenario Dispatching getFiles.initiate with no arguments
       * @expected Returns paginated response with files array
       */
      it("should fetch file list with default parameters", async () => {
        // Arrange
        const mockFiles = createMockFileList();
        server.use(
          http.get("/api/storage/files/", () => {
            return HttpResponse.json({ results: mockFiles, next: null });
          }),
        );

        // Act
        const result = await store.dispatch(
          fileApi.endpoints.getFiles.initiate({}),
        );

        // Assert
        expect(result.data).toBeDefined();
        expect(result.data?.results).toHaveLength(2);
        expect(result.data?.results[0].originalName).toBe("file1.txt");
      });

      /**
       * @description should append user_id query param when userId is provided
       * @scenario Dispatching getFiles with userId parameter
       * @expected Request URL includes user_id=123
       */
      it("should append user_id query param when userId is provided", async () => {
        // Arrange
        let requestUrl: URL | null = null;
        server.use(
          http.get("/api/storage/files/", ({ request }) => {
            requestUrl = new URL(request.url);
            return HttpResponse.json({ results: [], next: null });
          }),
        );

        // Act
        await store.dispatch(
          fileApi.endpoints.getFiles.initiate({ userId: 123 }),
        );

        // Assert
        expect(requestUrl).not.toBeNull();
        expect((requestUrl as unknown as URL).searchParams.get("user_id")).toBe(
          "123",
        );
      });

      /**
       * @description should append search query param when search is provided
       * @scenario Dispatching getFiles with search string
       * @expected Request URL includes search=test
       */
      it("should append search query param when search is provided", async () => {
        // Arrange
        let requestUrl: URL | null = null;
        server.use(
          http.get("/api/storage/files/", ({ request }) => {
            requestUrl = new URL(request.url);
            return HttpResponse.json({ results: [], next: null });
          }),
        );

        // Act
        await store.dispatch(
          fileApi.endpoints.getFiles.initiate({ search: "test" }),
        );

        // Assert
        expect(requestUrl).not.toBeNull();
        expect((requestUrl as unknown as URL).searchParams.get("search")).toBe(
          "test",
        );
      });
    });

    // ---------- getFile ----------
    describe("getFile", () => {
      /**
       * @description should fetch single file by id
       * @scenario Dispatching getFile.initiate with a specific id
       * @expected Returns file object with matching id
       */
      it("should fetch single file by id", async () => {
        // Arrange
        const mockFile = createMockFile(5, "single.txt");
        server.use(
          http.get("/api/storage/files/5/", () => {
            return HttpResponse.json(mockFile);
          }),
        );

        // Act
        const result = await store.dispatch(
          fileApi.endpoints.getFile.initiate(5),
        );

        // Assert
        expect(result.data).toBeDefined();
        expect(result.data).toEqual(mockFile);
      });
    });

    // ---------- deleteFile ----------
    describe("deleteFile", () => {
      /**
       * @description should send DELETE request for given file id
       * @scenario Dispatching deleteFile.initiate
       * @expected Request method is DELETE and URL ends with file id
       */
      it("should send DELETE request for given file id", async () => {
        // Arrange
        let requestMethod = "";
        let requestUrl = "";
        server.use(
          http.delete("/api/storage/files/7/", ({ request }) => {
            requestMethod = request.method;
            requestUrl = request.url;
            return new HttpResponse(null, { status: 204 });
          }),
        );

        // Act
        await store.dispatch(fileApi.endpoints.deleteFile.initiate(7));

        // Assert
        expect(requestMethod).toBe("DELETE");
        expect(requestUrl).toContain("/storage/files/7/");
      });
    });

    // ---------- renameFile ----------
    describe("renameFile", () => {
      /**
       * @description should send PATCH request with new originalName
       * @scenario Dispatching renameFile.initiate
       * @expected Request body contains correct originalName and method is PATCH
       */
      it("should send PATCH request with new originalName", async () => {
        // Arrange
        let requestBody: Record<string, unknown> | null = null;
        server.use(
          http.patch("/api/storage/files/3/rename/", async ({ request }) => {
            requestBody = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json(createMockFile(3, "newname.txt"));
          }),
        );

        // Act
        await store.dispatch(
          fileApi.endpoints.renameFile.initiate({
            id: 3,
            data: { originalName: "newname.txt" },
          }),
        );

        // Assert
        expect(requestBody).toEqual({ originalName: "newname.txt" });
      });
    });

    // ---------- updateComment ----------
    describe("updateComment", () => {
      /**
       * @description should send PATCH with comment payload
       * @scenario Dispatching updateComment.initiate
       * @expected Request body contains { comment: 'some comment' }
       */
      it("should send PATCH with comment payload", async () => {
        // Arrange
        let requestBody: Record<string, unknown> | null = null;
        server.use(
          http.patch("/api/storage/files/8/comment/", async ({ request }) => {
            requestBody = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json(createMockFile(8, "file.txt"));
          }),
        );

        // Act
        await store.dispatch(
          fileApi.endpoints.updateComment.initiate({
            id: 8,
            data: { comment: "review again" },
          }),
        );

        // Assert
        expect(requestBody).toEqual({ comment: "review again" });
      });
    });

    // ---------- generatePublicLink ----------
    describe("generatePublicLink", () => {
      /**
       * @description should send POST request to generate public link
       * @scenario Dispatching generatePublicLink.initiate
       * @expected Request method is POST and URL matches endpoint pattern
       */
      it("should send POST request to generate public link", async () => {
        // Arrange
        let requestMethod = "";
        const updatedFile = createMockFile(2, "shared.txt");
        updatedFile.hasPublicLink = true;
        updatedFile.publicLinkUrl = "/public/abc";
        server.use(
          http.post(
            "/api/storage/files/2/public-link/generate/",
            ({ request }) => {
              requestMethod = request.method;
              return HttpResponse.json(updatedFile);
            },
          ),
        );

        // Act
        const result = await store.dispatch(
          fileApi.endpoints.generatePublicLink.initiate(2),
        );

        // Assert
        expect(requestMethod).toBe("POST");
        expect(result.data).toBeDefined();
        expect(result.data?.hasPublicLink).toBe(true);
      });
    });

    // ---------- deletePublicLink ----------
    describe("deletePublicLink", () => {
      /**
       * @description should send DELETE request for public link
       * @scenario Dispatching deletePublicLink.initiate
       * @expected Method is DELETE and URL matches the endpoint
       */
      it("should send DELETE request for public link", async () => {
        // Arrange
        let requestMethod = "";
        const updatedFile = createMockFile(9, "noshare.txt");
        updatedFile.hasPublicLink = false;
        server.use(
          http.delete("/api/storage/files/9/public-link/", ({ request }) => {
            requestMethod = request.method;
            return HttpResponse.json(updatedFile);
          }),
        );

        // Act
        const result = await store.dispatch(
          fileApi.endpoints.deletePublicLink.initiate(9),
        );

        // Assert
        expect(requestMethod).toBe("DELETE");
        expect(result.data).toBeDefined();
        expect(result.data?.hasPublicLink).toBe(false);
      });
    });

    // ---------- getPublicFile ----------
    describe("getPublicFile", () => {
      /**
       * @description should fetch public file metadata by token without auth
       * @scenario Dispatching getPublicFile.initiate with token
       * @expected Returns file metadata and does not require Authorization header
       */
      it("should fetch public file metadata by token without auth", async () => {
        // Arrange
        clearAuthTokens(); // ensure no token
        const mockFile = createMockFile(99, "public.txt");
        server.use(
          http.get("/api/storage/public/abc-token/", () => {
            return HttpResponse.json(mockFile);
          }),
        );

        // Act
        const result = await store.dispatch(
          fileApi.endpoints.getPublicFile.initiate("abc-token"),
        );

        // Assert
        expect(result.data).toBeDefined();
        expect(result.data).toEqual(mockFile);
      });
    });

    // ---------- downloadPublicFile ----------
    describe("downloadPublicFile", () => {
      /**
       * @description should return a blob for public file download
       * @scenario Dispatching downloadPublicFile.initiate with token and filename
       * @expected Returns a Blob with correct content type
       */
      it("should return a blob for public file download", async () => {
        // Arrange
        server.use(
          http.get("/api/storage/public/pub-token/download/", () => {
            return new HttpResponse("public blob", {
              status: 200,
              headers: { "Content-Type": "application/pdf" },
            });
          }),
        );

        // Act
        const result = await store.dispatch(
          fileApi.endpoints.downloadPublicFile.initiate({
            token: "pub-token",
            filename: "download.pdf",
          }),
        );

        // Assert
        expect(result.data).toBeDefined();
        expect(result.data).toBeInstanceOf(Blob);
        expect(result.data?.type).toBe("application/pdf");
      });
    });
  });
});
