import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { store } from "@/app/store/store";
import { logout } from "@/entities/user";

import { getAccessTokenFromPersist } from "../utils/getPersistedAuthState";
import { fetchWithAuth } from "./fetchWithAuth";
import { getRefreshedToken } from "./tokenRefresh";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../utils/getPersistedAuthState", () => ({
  getAccessTokenFromPersist: vi.fn(),
}));

vi.mock("./tokenRefresh", () => ({
  getRefreshedToken: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  logout: vi.fn(),
}));

vi.mock("@/app/store/store", () => ({
  store: {
    dispatch: vi.fn(),
  },
}));

// =============================================================================
// TESTS
// =============================================================================

describe("fetchWithAuth", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", mockFetch);
    mockFetch.mockResolvedValue(new Response(null, { status: 200 }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /**
   * @description Should add Authorization header when token exists
   * @scenario Call fetchWithAuth with valid token
   * @expected fetch called with headers containing Authorization
   */
  it("should add Authorization header when token exists", async () => {
    const token = "test-token";
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(token);

    await fetchWithAuth("https://api.example.com");

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe("https://api.example.com");
    expect(options?.headers).toBeInstanceOf(Headers);
    const headers = options?.headers as Headers;
    expect(headers.get("Authorization")).toBe(`Bearer ${token}`);
  });

  /**
   * @description Should not add Authorization header when token is missing
   * @scenario Call fetchWithAuth with no token
   * @expected fetch called without Authorization header (headers.get returns
   *    null)
   */
  it("should not add Authorization header when token is missing", async () => {
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(null);

    await fetchWithAuth("https://api.example.com");

    const [_url, options] = mockFetch.mock.calls[0];
    const headers = options?.headers as Headers;
    expect(headers.get("Authorization")).toBeNull();
  });

  /**
   * @description Should merge provided headers with Authorization
   * @scenario Pass custom headers in init
   * @expected Headers include both custom and Authorization
   */
  it("should merge provided headers with Authorization", async () => {
    const token = "test-token";
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(token);
    const customHeaders = { "X-Custom": "value" };

    await fetchWithAuth("https://api.example.com", { headers: customHeaders });

    const [_url, options] = mockFetch.mock.calls[0];
    const headers = options?.headers as Headers;
    expect(headers.get("Authorization")).toBe(`Bearer ${token}`);
    expect(headers.get("X-Custom")).toBe("value");
  });

  /**
   * @description Should pass other init options to fetch
   * @scenario Pass method, body, etc.
   * @expected fetch receives same options
   */
  it("should pass other init options to fetch", async () => {
    const init: RequestInit = { method: "POST", body: "data" };
    await fetchWithAuth("https://api.example.com", init);

    const [_url, options] = mockFetch.mock.calls[0];
    expect(options?.method).toBe("POST");
    expect(options?.body).toBe("data");
  });

  /**
   * @description Should return response on success without retry
   * @scenario First request returns 200
   * @expected Response returned, getRefreshedToken not called
   */
  it("should return response on success without retry", async () => {
    const response = new Response(null, { status: 200 });
    mockFetch.mockResolvedValueOnce(response);

    const result = await fetchWithAuth("https://api.example.com");
    expect(result).toBe(response);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(getRefreshedToken).not.toHaveBeenCalled();
  });

  /**
   * @description Should retry on 401 if retry=true and token refresh succeeds
   * @scenario First request returns 401, getRefreshedToken returns new token,
   *    second request returns 200
   * @expected Two fetch calls, second with new token, final response returned
   */
  it("should retry on 401 if retry=true and token refresh succeeds", async () => {
    const token = "old-token";
    const newToken = "new-token";
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(token);
    vi.mocked(getRefreshedToken).mockResolvedValue(newToken);

    const fetchCalls: Array<{ headers: Record<string, string> }> = [];
    mockFetch.mockImplementation(async (_url, options) => {
      const headersObj: Record<string, string> = {};
      const headers = options?.headers as Headers;
      if (headers) {
        headers.forEach((value, key) => {
          headersObj[key] = value;
        });
      }
      fetchCalls.push({ headers: headersObj });
      // Возвращаем ответы последовательно: сначала 401, потом 200
      if (fetchCalls.length === 1) {
        return new Response(null, { status: 401 });
      } else {
        return new Response(null, { status: 200 });
      }
    });

    await fetchWithAuth("https://api.example.com");

    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(getAccessTokenFromPersist).toHaveBeenCalledTimes(1);

    expect(fetchCalls[0].headers.Authorization).toBe(`Bearer ${token}`);
    expect(fetchCalls[1].headers.Authorization).toBe(`Bearer ${newToken}`);
  });

  /**
   * @description Should not retry on 401 if retry=false
   * @scenario Call with retry=false, first request returns 401
   * @expected Response with 401 returned directly, no token refresh
   */
  it("should not retry on 401 if retry=false", async () => {
    const token = "test-token";
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(token);
    const errorResponse = new Response(null, { status: 401 });
    mockFetch.mockResolvedValueOnce(errorResponse);

    const result = await fetchWithAuth(
      "https://api.example.com",
      undefined,
      false,
    );

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(result).toBe(errorResponse);
    expect(getRefreshedToken).not.toHaveBeenCalled();
  });

  /**
   * @description Should dispatch logout and throw response when token refresh
   *    fails on 401
   * @scenario First request 401, getRefreshedToken throws error
   * @expected logout dispatched, store.dispatch called, original response
   *    thrown
   */
  it("should dispatch logout and throw response when token refresh fails on 401", async () => {
    const token = "old-token";
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(token);
    const refreshError = new Error("Refresh failed");
    vi.mocked(getRefreshedToken).mockRejectedValue(refreshError);

    const errorResponse = new Response(null, { status: 401 });
    mockFetch.mockResolvedValueOnce(errorResponse);

    await expect(fetchWithAuth("https://api.example.com")).rejects.toBe(
      errorResponse,
    );

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(getRefreshedToken).toHaveBeenCalledTimes(1);
    expect(store.dispatch).toHaveBeenCalledWith(logout());
  });

  /**
   * @description Should handle non-401 errors without retry
   * @scenario First request returns 500
   * @expected Response returned directly, no token refresh
   */
  it("should handle non-401 errors without retry", async () => {
    const errorResponse = new Response(null, { status: 500 });
    mockFetch.mockResolvedValueOnce(errorResponse);

    const result = await fetchWithAuth("https://api.example.com");
    expect(result).toBe(errorResponse);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(getRefreshedToken).not.toHaveBeenCalled();
  });

  /**
   * @description Should return second response even if it's not 200 after
   *    refresh
   * @scenario After token refresh, second request returns 403
   * @expected Response returned, logout not dispatched
   */
  it("should return second response even if it's not 200 after refresh", async () => {
    const token = "old-token";
    const newToken = "new-token";
    vi.mocked(getAccessTokenFromPersist).mockReturnValue(token);
    vi.mocked(getRefreshedToken).mockResolvedValue(newToken);

    const firstResponse = new Response(null, { status: 401 });
    const secondResponse = new Response(null, { status: 403 });
    mockFetch
      .mockResolvedValueOnce(firstResponse)
      .mockResolvedValueOnce(secondResponse);

    const result = await fetchWithAuth("https://api.example.com");
    expect(result).toBe(secondResponse);
    expect(store.dispatch).not.toHaveBeenCalled();
  });
});
