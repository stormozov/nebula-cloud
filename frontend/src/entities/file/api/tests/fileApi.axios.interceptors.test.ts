import { server } from "@tests/mocks/server";
import { HttpResponse, http } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("axios", async () => {
  const actual = await vi.importActual<typeof import("axios")>("axios");
  return actual;
});

// These mocks must be defined before importing fileApi.
vi.mock("@/shared/api", () => {
  const actual = vi.importActual("@/shared/api");
  return actual;
});

// We will mock only pieces we need via dynamic override after import.

const setLocalStoragePersistAuth = (value: string | null) => {
  if (value === null) {
    window.localStorage.removeItem("persist:auth");
    return;
  }
  window.localStorage.setItem("persist:auth", value);
};

describe("fileApi axios interceptors (uploadAxios)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    server.resetHandlers();
    vi.resetModules();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("uploadAxios request interceptor", () => {
    /**
     * @description Should not set Authorization header when persist:auth is missing
     * @scenario Calling uploadFile with valid File and localStorage has no "persist:auth"
     * @expected Authorization header must not be present in the outgoing request
     */
    it("should not set Authorization header when persist:auth is missing", async () => {
      // Arrange
      setLocalStoragePersistAuth(null);

      let authorizationHeader: string | null = null;

      server.use(
        http.post("/api/storage/files/", async ({ request }) => {
          authorizationHeader = request.headers.get("Authorization");
          return HttpResponse.json(
            {
              id: 1,
              originalName: "auth-none.txt",
              comment: null,
              size: 1,
              sizeFormatted: "1 B",
              uploadedAt: new Date().toISOString(),
              lastDownloaded: null,
              hasPublicLink: false,
              publicLinkUrl: null,
              downloadUrl: "/api/storage/files/1/download/",
            },
            { status: 201 },
          );
        }),
      );

      const { uploadFile } = await import("../fileApi");

      const mockFile = new File(["x"], "auth-none.txt", {
        type: "text/plain",
      });

      // Act
      await uploadFile({ file: mockFile });

      // Assert
      expect(authorizationHeader).toBeNull();
    });

    /**
     * @description Should not set Authorization header when persist:auth contains invalid JSON
     * @scenario Calling uploadFile with valid File and localStorage persist:auth has invalid JSON
     * @expected Authorization header must not be present
     */
    it("should not set Authorization header when persist:auth contains invalid JSON", async () => {
      // Arrange
      setLocalStoragePersistAuth("not-json");

      let authorizationHeader: string | null = null;

      server.use(
        http.post("/api/storage/files/", async ({ request }) => {
          authorizationHeader = request.headers.get("Authorization");
          return HttpResponse.json(
            {
              id: 2,
              originalName: "invalid-json.txt",
              comment: null,
              size: 1,
              sizeFormatted: "1 B",
              uploadedAt: new Date().toISOString(),
              lastDownloaded: null,
              hasPublicLink: false,
              publicLinkUrl: null,
              downloadUrl: "/api/storage/files/2/download/",
            },
            { status: 201 },
          );
        }),
      );

      const { uploadFile } = await import("../fileApi");

      const mockFile = new File(["x"], "invalid-json.txt", {
        type: "text/plain",
      });

      // Act
      await uploadFile({ file: mockFile });

      // Assert
      expect(authorizationHeader).toBeNull();
    });

    /**
     * @description Should not set Authorization header when persist:auth has no accessToken
     * @scenario Calling uploadFile with valid File and persist:auth JSON without accessToken
     * @expected Authorization header must not be present
     */
    it("should not set Authorization header when persist:auth has no accessToken", async () => {
      // Arrange
      setLocalStoragePersistAuth(JSON.stringify({ notAccessToken: "x" }));

      let authorizationHeader: string | null = null;

      server.use(
        http.post("/api/storage/files/", async ({ request }) => {
          authorizationHeader = request.headers.get("Authorization");
          return HttpResponse.json(
            {
              id: 3,
              originalName: "no-access-token.txt",
              comment: null,
              size: 1,
              sizeFormatted: "1 B",
              uploadedAt: new Date().toISOString(),
              lastDownloaded: null,
              hasPublicLink: false,
              publicLinkUrl: null,
              downloadUrl: "/api/storage/files/3/download/",
            },
            { status: 201 },
          );
        }),
      );

      const { uploadFile } = await import("../fileApi");

      const mockFile = new File(["x"], "no-access-token.txt", {
        type: "text/plain",
      });

      // Act
      await uploadFile({ file: mockFile });

      // Assert
      expect(authorizationHeader).toBeNull();
    });
  });

  describe("uploadAxios response interceptor", () => {
    /**
     * @description Should refresh token and retry upload request when server returns 401
     * @scenario uploadFile triggers axios interceptor with 401 and getRefreshedToken resolves successfully
     * @expected upload request should be retried once with refreshed Authorization header
     */
    it("should refresh token and retry upload request when server returns 401", async () => {
      // Arrange
      setLocalStoragePersistAuth(JSON.stringify({ accessToken: "old-token" }));

      const apiModule = await import("@/shared/api");
      const getRefreshedTokenSpy = vi
        .spyOn(apiModule, "getRefreshedToken")
        .mockResolvedValue("new-token");

      let callCount = 0;

      server.use(
        http.post("/api/storage/files/", async ({ request }) => {
          callCount += 1;
          if (callCount === 1) {
            return new HttpResponse(null, { status: 401 });
          }
          const authorizationHeader = request.headers.get("Authorization");
          expect(authorizationHeader).toBe("Bearer new-token");

          return HttpResponse.json(
            {
              id: 10,
              originalName: "retry.txt",
              comment: null,
              size: 1,
              sizeFormatted: "1 B",
              uploadedAt: new Date().toISOString(),
              lastDownloaded: null,
              hasPublicLink: false,
              publicLinkUrl: null,
              downloadUrl: "/api/storage/files/10/download/",
            },
            { status: 201 },
          );
        }),
      );

      const { uploadFile } = await import("../fileApi");

      const mockFile = new File(["x"], "retry.txt", { type: "text/plain" });

      // Act
      const result = await uploadFile({ file: mockFile });

      // Assert
      expect(result.originalName).toBe("retry.txt");
      expect(callCount).toBe(2);
      expect(getRefreshedTokenSpy).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should dispatch logout and reject when token refresh fails after 401
     * @scenario uploadFile triggers 401 and getRefreshedToken throws
     * @expected logout() is dispatched and uploadFile rejects
     */
    it("should dispatch logout and reject when refresh fails after 401", async () => {
      // Arrange
      setLocalStoragePersistAuth(JSON.stringify({ accessToken: "old-token" }));

      const refreshError = new Error("refresh-failed");

      const apiModule = await import("@/shared/api");
      vi.spyOn(apiModule, "getRefreshedToken").mockRejectedValue(refreshError);

      const dispatchSpy = vi.fn();

      vi.mock("@/entities/user", async () => ({
        logout: vi.fn(() => ({ type: "auth/logout" })),
      }));

      vi.mock("@/app/store/store", async () => {
        return {
          store: {
            dispatch: vi.fn(),
          },
        };
      });

      const apiStoreModule = await import("@/app/store/store");
      vi.spyOn(apiStoreModule.store, "dispatch").mockImplementation(
        dispatchSpy,
      );
      vi.mocked(apiStoreModule.store.dispatch).mockImplementation(dispatchSpy);

      server.use(
        http.post("/api/storage/files/", () => {
          return new HttpResponse(null, { status: 401 });
        }),
      );

      const { uploadFile } = await import("../fileApi");

      const mockFile = new File(["x"], "refresh-fail.txt", {
        type: "text/plain",
      });

      // Act & Assert
      await expect(uploadFile({ file: mockFile })).rejects.toBeInstanceOf(
        Error,
      );
      expect(apiModule.getRefreshedToken).toHaveBeenCalledTimes(1);
      expect(dispatchSpy).toHaveBeenCalled();
    });
  });
});
