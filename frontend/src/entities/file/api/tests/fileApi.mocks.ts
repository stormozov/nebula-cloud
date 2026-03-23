import { delay, HttpResponse, http } from "msw";
import { vi } from "vitest";

import type { IFile, IFileComment, IFileRename } from "../../model/types";

// =============================================================================
// MOCK HELPERS
// =============================================================================

/**
 * Creates a mock file object for testing
 * @param id - File identifier
 * @param originalName - File name
 * @returns Mock IFile object
 */
export const createMockFile = (
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

/**
 * Creates mock file list for testing
 * @param count - Number of files to create
 * @returns Array of mock IFile objects
 */
export const createMockFileList = (count: number = 3): IFile[] => {
  return Array.from({ length: count }, (_, index) =>
    createMockFile(index + 1, `file${index + 1}.txt`),
  );
};

/**
 * Mock FormData for file upload testing
 */
export class MockFormData {
  private data: Map<string, string | File> = new Map();

  append(key: string, value: string | File): void {
    this.data.set(key, value);
  }

  get(key: string): string | File | null {
    return this.data.get(key) || null;
  }

  has(key: string): boolean {
    return this.data.has(key);
  }
}

// =============================================================================
// LOCALSTORAGE MOCK
// =============================================================================

/**
 * Mock localStorage for authentication testing
 */
export const localStorageMock = {
  getItem: vi.fn((key: string): string | null => {
    if (key === "persist:auth") {
      return localStorageMock._authData;
    }
    return null;
  }),
  setItem: vi.fn((key: string, value: string): void => {
    if (key === "persist:auth") {
      localStorageMock._authData = value;
    }
  }),
  removeItem: vi.fn((key: string): void => {
    if (key === "persist:auth") {
      localStorageMock._authData = null;
    }
  }),
  clear: vi.fn(),
  _authData: null as string | null,
};

/**
 * Sets up localStorage with valid auth token
 * @param accessToken - Access token to store
 */
export const setValidAuthToken = (
  accessToken: string = "mock_access_token",
): void => {
  const tokenData = JSON.stringify({
    accessToken: JSON.stringify(accessToken),
  });
  localStorageMock._authData = tokenData;
  localStorageMock.getItem.mockReturnValue(tokenData);
};

/**
 * Clears auth token from localStorage mock
 */
export const clearAuthToken = (): void => {
  localStorageMock._authData = null;
  localStorageMock.getItem.mockReturnValue(null);
};

/**
 * Sets up localStorage with invalid JSON token
 */
export const setInvalidAuthToken = (): void => {
  localStorageMock._authData = "invalid-json";
  localStorageMock.getItem.mockReturnValue("invalid-json");
};

// =============================================================================
// MSW HANDLERS
// =============================================================================

/**
 * MSW handlers for file API endpoints
 */
export const fileApiHandlers = [
  // GET /storage/files/ - Get file list
  http.get("/api/storage/files/", async () => {
    await delay(100); // Simulate network delay
    return HttpResponse.json(createMockFileList(3));
  }),

  // GET /storage/files/:id/ - Get single file
  http.get("/api/storage/files/:id/", async ({ params }) => {
    await delay(100);
    const id = Number(params.id);

    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }

    return HttpResponse.json(createMockFile(id, `file${id}.txt`));
  }),

  // DELETE /storage/files/:id/ - Delete file
  http.delete("/api/storage/files/:id/", async ({ params }) => {
    await delay(100);
    const id = Number(params.id);

    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }

    return HttpResponse.json(null, { status: 204 });
  }),

  // PATCH /storage/files/:id/rename/ - Rename file
  http.patch("/api/storage/files/:id/rename/", async ({ params, request }) => {
    await delay(100);
    const id = Number(params.id);
    const body = (await request.json()) as IFileRename;

    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }

    return HttpResponse.json(createMockFile(id, body.originalName), {
      status: 200,
    });
  }),

  // PATCH /storage/files/:id/comment/ - Update comment
  http.patch("/api/storage/files/:id/comment/", async ({ params, request }) => {
    await delay(100);
    const id = Number(params.id);
    const body = (await request.json()) as IFileComment;

    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }

    const file = createMockFile(id);
    file.comment = body.comment;

    return HttpResponse.json(file, { status: 200 });
  }),

  // POST /storage/files/:id/public-link/generate/ - Generate public link
  http.post(
    "/api/storage/files/:id/public-link/generate/",
    async ({ params }) => {
      await delay(100);
      const id = Number(params.id);

      if (id === 999) {
        return HttpResponse.json({ detail: "File not found" }, { status: 404 });
      }

      const file = createMockFile(id);
      file.hasPublicLink = true;
      file.publicLinkUrl = `https://example.com/public/${id}`;

      return HttpResponse.json(file, { status: 200 });
    },
  ),

  // DELETE /storage/files/:id/public-link/ - Delete public link
  http.delete("/api/storage/files/:id/public-link/", async ({ params }) => {
    await delay(100);
    const id = Number(params.id);

    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }

    const file = createMockFile(id);
    file.hasPublicLink = false;
    file.publicLinkUrl = null;

    return HttpResponse.json(file, { status: 200 });
  }),

  // POST /storage/files/ - Upload file
  http.post("/api/storage/files/", async ({ request }) => {
    await delay(100);
    const formData = await request.formData();
    const file = formData.get("file") as File;
    const comment = formData.get("comment") as string | null;

    if (!file) {
      return HttpResponse.json({ detail: "No file provided" }, { status: 400 });
    }

    const newFile = createMockFile(100, file.name);
    if (comment) {
      newFile.comment = comment;
    }

    return HttpResponse.json(newFile, { status: 201 });
  }),
];

/**
 * MSW handlers for error scenarios
 */
export const fileApiErrorHandlers = [
  // GET /storage/files/ - Server error
  http.get("/api/storage/files/", async () => {
    await delay(100);
    return HttpResponse.json(
      { detail: "Internal server error" },
      { status: 500 },
    );
  }),

  // POST /storage/files/ - Upload error
  http.post("/api/storage/files/", async () => {
    await delay(100);
    return HttpResponse.json({ detail: "Upload failed" }, { status: 500 });
  }),

  // DELETE /storage/files/:id/ - Delete error
  http.delete("/api/storage/files/:id/", async () => {
    await delay(100);
    return HttpResponse.json({ detail: "Delete failed" }, { status: 500 });
  }),
];

// =============================================================================
// AXIOS MOCK
// =============================================================================

/**
 * Mock axios for uploadFile function testing
 */
export const axiosMock = {
  post: vi.fn(),
  create: vi.fn(() => ({
    post: vi.fn(),
    interceptors: {
      request: {
        use: vi.fn(),
      },
      response: {
        use: vi.fn(),
      },
    },
  })),
};

/**
 * Sets up successful axios upload mock
 * @param responseData - Response data to return
 */
export const setupAxiosUploadSuccess = (responseData: IFile): void => {
  axiosMock.post.mockResolvedValueOnce({ data: responseData });
};

/**
 * Sets up failed axios upload mock
 * @param error - Error to throw
 */
export const setupAxiosUploadError = (error: Error): void => {
  axiosMock.post.mockRejectedValueOnce(error);
};

/**
 * Sets up axios upload with progress callback
 * @param responseData - Response data to return
 * @param progressCallback - Callback to invoke with progress
 */
export const setupAxiosUploadWithProgress = (
  responseData: IFile,
  progressCallback?: (progress: number) => void,
): void => {
  axiosMock.post.mockImplementationOnce(async (_url, _data, config) => {
    // Simulate progress
    if (config.onUploadProgress && progressCallback) {
      config.onUploadProgress({ loaded: 50, total: 100 });
      progressCallback(50);
      config.onUploadProgress({ loaded: 100, total: 100 });
      progressCallback(100);
    }
    return { data: responseData };
  });
};

// =============================================================================
// REDUX SLICE ACTIONS MOCK
// =============================================================================

/**
 * Mock Redux slice actions
 */
export const sliceActionsMock = {
  setLoading: vi.fn(),
  setFileList: vi.fn(),
  setError: vi.fn(),
  removeFile: vi.fn(),
  updateFile: vi.fn(),
  setSelectedFile: vi.fn(),
  setUploading: vi.fn(),
  setUploadProgress: vi.fn(),
  clearError: vi.fn(),
  resetState: vi.fn(),
};

/**
 * Clears all slice action mocks
 */
export const clearSliceActionMocks = (): void => {
  Object.values(sliceActionsMock).forEach((mock) => {
    if (vi.isMockFunction(mock)) {
      mock.mockClear();
    }
  });
};

// =============================================================================
// ENVIRONMENT MOCK
// =============================================================================

/**
 * Sets up environment variables mock
 * @param baseUrl - API base URL
 */
export const setupEnvMock = (baseUrl: string = "/api"): void => {
  vi.stubGlobal("import.meta", {
    env: {
      VITE_API_BASE_URL: baseUrl,
    },
  });
};

/**
 * Clears environment variables mock
 */
export const clearEnvMock = (): void => {
  vi.unstubAllGlobals();
};

// =============================================================================
// TEST STORE FACTORY
// =============================================================================

/**
 * Creates a test store with fileApi configured
 * @returns Configured Redux store
 */
export const createTestStore = async (): Promise<
  ReturnType<typeof import("@reduxjs/toolkit").configureStore>
> => {
  const { configureStore } = await import("@reduxjs/toolkit");
  const { fileApi } = await import("../fileApi");
  const { fileSlice } = await import("../../model/slice");

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
// SETUP/TEARDOWN UTILITIES
// =============================================================================

/**
 * Sets up all mocks before test
 */
export const setupFileApiMocks = (): void => {
  // Setup localStorage
  Object.defineProperty(window, "localStorage", {
    value: localStorageMock,
    writable: true,
  });

  // Setup FormData
  vi.stubGlobal("FormData", MockFormData);

  // Setup environment
  setupEnvMock();

  // Setup axios mock
  vi.mock("axios", () => ({
    default: axiosMock,
    __esModule: true,
  }));

  // Setup slice actions mock
  vi.mock("./slice", async (importOriginal) => {
    const actual = await importOriginal<typeof import("../../model/slice")>();
    return {
      ...actual,
      setLoading: sliceActionsMock.setLoading,
      setFileList: sliceActionsMock.setFileList,
      setError: sliceActionsMock.setError,
      removeFile: sliceActionsMock.removeFile,
      updateFile: sliceActionsMock.updateFile,
      setSelectedFile: sliceActionsMock.setSelectedFile,
      setUploading: sliceActionsMock.setUploading,
      setUploadProgress: sliceActionsMock.setUploadProgress,
      clearError: sliceActionsMock.clearError,
      resetState: sliceActionsMock.resetState,
    };
  });
};

/**
 * Tears down all mocks after test
 */
export const teardownFileApiMocks = (): void => {
  vi.clearAllMocks();
  clearEnvMock();
  clearSliceActionMocks();
};
