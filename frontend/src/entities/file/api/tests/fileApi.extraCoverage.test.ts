import { server } from "@tests/mocks/server";
import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/shared/api", async () => {
  const actual = await vi.importActual<typeof import("@/shared/api")>(
    "@/shared/api",
  );

  return {
    ...actual,
    API_BASE_URL: "/api",
    fetchWithAuth: vi.fn((url: string, init?: RequestInit) =>
      fetch(url, init),
    ),
  };
});


vi.mock("@/shared/utils", () => ({
  downloadFile: vi.fn(),
}));

const { getImageBlobFromApi, downloadFileFromApi } = await import(
  "../fileApi"
);

describe("fileApi extra coverage", () => {
  afterEach(() => {
    vi.clearAllMocks();
    server.resetHandlers();
  });

  describe("downloadFileFromApi", () => {
    /**
     * @description should return { error } from downloadPublicFile queryFn on fetch failure
     * @scenario Calling downloadFileFromApi with getImageBlobFromApi returning non-Response error
     * @expected console.error is called and function does not throw
     */
    it("should log error and not throw when getImageBlobFromApi throws non-401 error", async () => {
      // Arrange
      const consoleErrorSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      server.use(
        http.get("/api/storage/files/30/download/", () => {
          return new HttpResponse(null, { status: 500 });
        }),
      );

      // Act
      await downloadFileFromApi(30, "x.txt");

      // Assert
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        "Download failed:",
        expect.any(Error),
      );

      consoleErrorSpy.mockRestore();
    });
  });

  describe("getImageBlobFromApi", () => {
    /**
     * @description should rethrow when server returns 401
     * @scenario Calling getImageBlobFromApi with fileId where endpoint returns 401
     * @expected Promise rejects with Response (401)
     */
    it("should rethrow Response when server returns 401", async () => {
      // Arrange
      server.use(
        http.get("/api/storage/files/31/download/", () => {
          return new HttpResponse(null, { status: 401 });
        }),
      );

      // Act & Assert
      await expect(getImageBlobFromApi(31)).rejects.toThrow();
    });
  });
});

