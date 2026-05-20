import { server } from "@tests/mocks/server";
import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/shared/api", async () => {
  const actual =
    await vi.importActual<typeof import("@/shared/api")>("@/shared/api");

  return {
    ...actual,
    API_BASE_URL: "/api",
  };
});

vi.mock("@/shared/utils", () => ({
  downloadFile: vi.fn(),
}));

const { fileApi } = await import("../fileApi");

import { configureStore } from "@reduxjs/toolkit";

describe("fileApi downloadPublicFile error branch", () => {
  afterEach(() => {
    vi.clearAllMocks();
    server.resetHandlers();
  });

  describe("downloadPublicFile queryFn", () => {
    /**
     * @description should return { error } when fetch fails
     * @scenario Dispatching downloadPublicFile.initiate with MSW returning 500
     * @expected RTK Query result should be an error and not a Blob payload
     */
    it("should return error object when response is not ok", async () => {
      // Arrange
      server.use(
        http.get("/api/storage/public/bad-token/download/", () => {
          return new HttpResponse(null, { status: 500 });
        }),
      );

      const store = configureStore({
        reducer: {
          [fileApi.reducerPath]: fileApi.reducer,
        },
        middleware: (getDefaultMiddleware) =>
          getDefaultMiddleware().concat(fileApi.middleware),
      });

      // Act
      const result = await store.dispatch(
        fileApi.endpoints.downloadPublicFile.initiate({
          token: "bad-token",
          filename: "x.pdf",
        }),
      );

      // Assert
      expect(result).toBeDefined();
      expect("error" in result).toBe(true);
    });
  });
});
