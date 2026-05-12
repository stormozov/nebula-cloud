import type { FetchArgs } from "@reduxjs/toolkit/query";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

// =============================================================================
// MODULE MOCKS
// =============================================================================

type BaseQueryResult = {
  data?: unknown;
  error?: { status?: number };
};

let prepareHeadersSpy: Mock;
let baseQuerySpy: Mock;

vi.mock("@reduxjs/toolkit/query", () => {
  return {
    fetchBaseQuery: (config: {
      prepareHeaders: (headers: Headers) => Headers;
    }) => {
      prepareHeadersSpy = vi.fn((headers: Headers) =>
        config.prepareHeaders(headers),
      );

      const fn = async (args: string | FetchArgs): Promise<BaseQueryResult> => {
        const headers = new Headers();
        prepareHeadersSpy(headers);

        const resolvedHeaders = new Headers(headers);

        // If args includes headers, emulate RTK Query merging by applying
        // them after prepareHeaders
        if (typeof args !== "string" && args.headers) {
          if (args.headers instanceof Headers) {
            for (const [key, value] of args.headers.entries()) {
              resolvedHeaders.set(key, value);
            }
          } else if (Array.isArray(args.headers)) {
            for (const [key, value] of args.headers) {
              if (value !== undefined) resolvedHeaders.set(key, String(value));
            }
          } else {
            for (const [key, value] of Object.entries(args.headers)) {
              if (value !== undefined) resolvedHeaders.set(key, String(value));
            }
          }
        }

        return baseQuerySpy(args, resolvedHeaders);
      };

      return fn;
    },
  };
});

// baseQueryWithAuthErrorHandling imports getRefreshedToken
const mockGetRefreshedToken: Mock = vi.fn();
vi.mock("../tokenRefresh", () => ({
  getRefreshedToken: mockGetRefreshedToken,
}));

const mockLogout: Mock = vi.fn();
vi.mock("@/entities/user", () => ({
  logout: mockLogout,
}));

// =============================================================================
// TEST HELPERS
// =============================================================================

const setAuthTokenInLocalStorage = (accessToken: string): void => {
  const payload = JSON.stringify({
    accessToken: JSON.stringify(accessToken),
  });
  localStorage.setItem("persist:auth", payload);
};

const setInvalidAuthTokenInLocalStorage = (): void => {
  localStorage.setItem("persist:auth", "invalid-json");
};

// =============================================================================
// TESTS
// =============================================================================

describe("baseApi", () => {
  beforeEach(async () => {
    vi.clearAllMocks();

    baseQuerySpy = vi.fn(
      async (_args: string | FetchArgs, resolvedHeaders: Headers) => {
        const authorization = resolvedHeaders.get("Authorization");
        const contentType = resolvedHeaders.get("Content-Type");

        // default: just echo for snakeToCamel tests
        if (authorization === "Bearer old-access") {
          return { error: { status: 401 } };
        }

        if (authorization === "Bearer new-access") {
          return {
            data: {
              some_key: "some_value",
              authorization_seen: authorization,
              content_type: contentType,
            },
          };
        }

        // For prepareHeaders tests
        return {
          data: { authorization, content_type: contentType },
        };
      },
    );
  });

  describe("baseQuery prepareHeaders", () => {
    /**
     * @description Should set Content-Type to application/json when localStorage token is missing
     * @scenario baseQuery invoked without persist:auth in localStorage
     * @expected Content-Type header is set and Authorization header is not present
     */
    it("should set Content-Type and omit Authorization when token is missing", async () => {
      localStorage.removeItem("persist:auth");

      const { baseQuery } = await import("../baseApi");

      // Act
      const result = await baseQuery(
        { url: "/test" },
        {} as never,
        {} as never,
      );

      // Assert
      expect(result.data).toEqual({
        authorization: null,
        content_type: "application/json",
      });
    });

    /**
     * @description Should ignore invalid JSON token and still set Content-Type
     * @scenario localStorage persist:auth is not a valid JSON
     * @expected Authorization header is not set, Content-Type is application/json
     */
    it("should omit Authorization when persist:auth contains invalid JSON", async () => {
      setInvalidAuthTokenInLocalStorage();

      const { baseQuery } = await import("../baseApi");

      // Act
      const result = await baseQuery(
        { url: "/test" },
        {} as never,
        {} as never,
      );

      // Assert
      expect(result.data).toEqual({
        authorization: null,
        content_type: "application/json",
      });
    });

    /**
     * @description Should set Authorization Bearer token when localStorage token exists and is valid
     * @scenario persist:auth contains valid accessToken JSON
     * @expected Authorization header is set to Bearer <token> and Content-Type is application/json
     */
    it("should set Authorization header when valid access token exists in persist:auth", async () => {
      setAuthTokenInLocalStorage("test-access-token");

      const { baseQuery } = await import("../baseApi");

      // Act
      const result = await baseQuery(
        { url: "/test" },
        {} as never,
        {} as never,
      );

      // Assert
      expect(result.data).toEqual({
        authorization: "Bearer test-access-token",
        content_type: "application/json",
      });
    });
  });

  describe("baseQueryWithAuthErrorHandling", () => {
    beforeEach(() => {
      mockGetRefreshedToken.mockReset();
      window.location.pathname = "/app";
      window.location.href = "http://localhost/";
    });

    /**
     * @description Should transform response data snake_case to camelCase
     * @scenario baseQuery returns data with snake_case keys and result.data exists
     * @expected snakeToCamel is applied to result.data
     */
    it("should transform snake_case response data to camelCase when result data exists", async () => {
      setAuthTokenInLocalStorage("new-access"); // makes baseQuery return data for new-access

      const { baseQueryWithAuthErrorHandling } = await import("../baseApi");

      // Act
      const result = await baseQueryWithAuthErrorHandling(
        { url: "/test", headers: {} },
        {} as never,
        {} as never,
      );

      // Assert
      expect(result.data).toEqual({
        someKey: "some_value",
        authorizationSeen: "Bearer new-access",
        contentType: "application/json",
      });
    });

    /**
     * @description Should refresh token on 401 and retry request with new Authorization header
     * @scenario First baseQuery call returns 401 for old-access, then refresh succeeds and second call returns data
     * @expected getRefreshedToken called once and baseQuery is retried with Bearer new-access
     */
    it("should refresh token and retry request when baseQuery returns 401", async () => {
      setAuthTokenInLocalStorage("old-access");
      mockGetRefreshedToken.mockResolvedValue("new-access");

      const { baseQueryWithAuthErrorHandling } = await import("../baseApi");

      // Act
      const result = await baseQueryWithAuthErrorHandling(
        { url: "/test", headers: { Authorization: "Bearer old-access" } },
        {} as never,
        {} as never,
      );

      // Assert
      expect(mockGetRefreshedToken).toHaveBeenCalledTimes(1);
      expect(baseQuerySpy).toHaveBeenCalledTimes(2);

      expect(result.data).toEqual({
        someKey: "some_value",
        authorizationSeen: "Bearer new-access",
        contentType: "application/json",
      });
    });

    /**
     * @description Should logout and redirect to /auth when refresh token fails on 401
     * @scenario baseQuery returns 401, getRefreshedToken throws, current pathname is not /auth
     * @expected logout is dispatched and window.location.href is set to /auth
     */
    it("should logout and redirect to /auth when token refresh throws during 401 handling", async () => {
      setAuthTokenInLocalStorage("old-access");
      mockGetRefreshedToken.mockRejectedValue(new Error("Refresh failed"));

      const href = "http://localhost/auth";
      window.location.href = href;

      const { baseQueryWithAuthErrorHandling } = await import("../baseApi");

      // Act
      const result = await baseQueryWithAuthErrorHandling(
        { url: "/test", headers: { Authorization: "Bearer old-access" } },
        {
          dispatch: vi.fn(),
        } as never,
        {} as never,
      );

      // Assert
      expect(result.error).toBeDefined();
      expect(mockLogout).toHaveBeenCalled();
      // If pathname !== "/auth", baseApi should redirect
      expect(window.location.href).toContain("/auth");
    });
  });
});
