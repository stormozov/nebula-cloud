import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/entities/user", () => ({
  logout: vi.fn(),
  setTokens: vi.fn(),
}));

vi.mock("../../utils", () => ({
  getRefreshTokenFromPersist: vi.fn(),
}));

vi.mock("../apiBaseUrl", () => ({
  API_BASE_URL: "https://mock-api.example.com",
}));

vi.mock("@/app/store/store", () => ({
  store: {
    dispatch: vi.fn(),
  },
}));

// =============================================================================
// HELPERS
// =============================================================================

const localStorageStub = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
const fetchStub = vi.fn();

// ---------- Module under test & fresh mocks ----------
let tokenRefreshModule: typeof import("../tokenRefresh");
let mockLogout: Mock;
let mockSetTokens: Mock;
let mockGetRefreshToken: Mock;
let mockStoreDispatch: Mock;

beforeEach(async () => {
  vi.resetModules();

  // Restore global stubs after resetModules clears them
  vi.stubGlobal("localStorage", localStorageStub);
  vi.stubGlobal("fetch", fetchStub);

  // Re-import everything so our references point to the fresh mocks
  const userModule = await import("@/entities/user");
  const utilsModule = await import("../../utils");
  const storeModule = await import("@/app/store/store");

  mockLogout = userModule.logout as unknown as Mock;
  mockSetTokens = userModule.setTokens as unknown as Mock;
  mockGetRefreshToken = utilsModule.getRefreshTokenFromPersist as Mock;
  mockStoreDispatch = storeModule.store.dispatch as Mock;

  // Useful for assertions: make logout return a predictable action object
  mockLogout.mockReturnValue({ type: "LOGOUT" });

  tokenRefreshModule = await import("../tokenRefresh");
});

// =============================================================================
// TESTS
// =============================================================================

describe("tokenRefresh", () => {
  // ---------------------------------------------------------------------------
  // subscribeTokenRefresh & onRefreshed
  // ---------------------------------------------------------------------------
  describe("subscribeTokenRefresh & onRefreshed", () => {
    /**
     * @description Should resolve all concurrent callers with the same token when refreshing
     * @scenario Two concurrent getRefreshedToken calls, second is queued while first completes
     * @expected Both calls resolve with the same new token (proves subscribe + onRefreshed)
     */
    it("should resolve all concurrent callers with the same token when refreshing", async () => {
      // Arrange
      const newAccess = "shared-access";
      mockGetRefreshToken.mockReturnValue("valid-refresh");

      let resolveFetch: ((value: unknown) => void) | undefined;
      const fetchPromise = new Promise((resolve) => {
        resolveFetch = resolve;
      });
      fetchStub.mockReturnValue(
        fetchPromise.then(() => ({
          ok: true,
          json: vi
            .fn()
            .mockResolvedValue({ access: newAccess, refresh: "new-refresh" }),
        })),
      );

      // Act
      const first = tokenRefreshModule.getRefreshedToken();
      const second = tokenRefreshModule.getRefreshedToken(); // subscribes

      resolveFetch?.(undefined);
      const [token1, token2] = await Promise.all([first, second]);

      // Assert
      expect(token1).toBe(newAccess);
      expect(token2).toBe(newAccess);
      expect(fetchStub).toHaveBeenCalledTimes(1); // only one refresh
    });

    /**
     * @description Should start a new refresh for a new call after previous refresh completed
     * @scenario After a successful refresh, a new call should trigger a fresh refresh (no leftover subscribers)
     * @expected Second refresh cycle starts a new fetch (proves onRefreshed cleared subscribers)
     */
    it("should start a new refresh for a new call after previous refresh completed", async () => {
      // Arrange – first successful refresh
      const token1 = "token-1";
      const token2 = "token-2";
      mockGetRefreshToken.mockReturnValue("refresh-1");
      fetchStub.mockResolvedValueOnce({
        ok: true,
        json: vi
          .fn()
          .mockResolvedValue({ access: token1, refresh: "new-refresh-1" }),
      });

      const first = await tokenRefreshModule.getRefreshedToken();
      expect(first).toBe(token1);

      // Arrange – next refresh
      mockGetRefreshToken.mockReturnValue("refresh-2");
      fetchStub.mockResolvedValueOnce({
        ok: true,
        json: vi
          .fn()
          .mockResolvedValue({ access: token2, refresh: "new-refresh-2" }),
      });

      // Act
      const second = await tokenRefreshModule.getRefreshedToken();

      // Assert – second call triggers a new fetch (subscribers were cleared)
      expect(second).toBe(token2);
      expect(fetchStub).toHaveBeenCalledTimes(2);
    });

    /**
     * @description Should leave queued callers unresolved after refresh failure
     * @scenario First refresh fails, second call is queued. After failure, second call never resolves.
     * @expected The queued promise stays pending (subscribers not notified), subsequent refresh works.
     */
    it("should leave queued callers unresolved after refresh failure", async () => {
      // Arrange
      mockGetRefreshToken.mockReturnValue("fail-refresh");
      fetchStub.mockResolvedValue({ ok: false, json: vi.fn() });

      // Act
      const first = tokenRefreshModule.getRefreshedToken(); // will fail
      const queued = tokenRefreshModule.getRefreshedToken(); // subscribes

      await expect(first).rejects.toThrow("Refresh failed");

      // Assert – queued promise never resolves
      const timeout = new Promise<string>((resolve) =>
        setTimeout(() => resolve("timeout"), 50),
      );
      const result = await Promise.race([queued, timeout]);
      expect(result).toBe("timeout");

      // A new call should work normally
      mockGetRefreshToken.mockReturnValue("fresh-refresh");
      fetchStub.mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          access: "fresh-access",
          refresh: "fresh-refresh",
        }),
      });
      const fresh = await tokenRefreshModule.getRefreshedToken();
      expect(fresh).toBe("fresh-access");
    });
  });

  // ---------------------------------------------------------------------------
  // getRefreshedToken
  // ---------------------------------------------------------------------------
  describe("getRefreshedToken", () => {
    /**
     * @description Should successfully refresh and update tokens
     * @scenario Refresh token exists, API responds with 200 and new tokens
     * @expected setTokens and localStorage.setItem are called, returns new access token
     */
    it("should return new access token and persist tokens on success", async () => {
      // Arrange
      const oldRefresh = "old-refresh-token";
      const newTokens = { access: "new-access", refresh: "new-refresh" };

      mockGetRefreshToken.mockReturnValue(oldRefresh);
      fetchStub.mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue(newTokens),
      });

      // Act
      const access = await tokenRefreshModule.getRefreshedToken();

      // Assert
      expect(fetchStub).toHaveBeenCalledWith(
        "https://mock-api.example.com/auth/refresh/",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh: oldRefresh }),
        },
      );
      expect(mockSetTokens).toHaveBeenCalledWith(newTokens);
      expect(localStorageStub.setItem).toHaveBeenCalledWith(
        "persist:auth",
        JSON.stringify({
          accessToken: JSON.stringify(newTokens.access),
          refreshToken: JSON.stringify(newTokens.refresh),
        }),
      );
      expect(access).toBe(newTokens.access);
    });

    /**
     * @description Should logout and throw when refresh token is absent
     * @scenario getRefreshTokenFromPersist returns falsy value
     * @expected throws 'No refresh token', dispatch logout action
     */
    it('should throw "No refresh token" and logout when refresh token is absent', async () => {
      // Arrange
      mockGetRefreshToken.mockReturnValue(null);

      // Act & Assert
      await expect(tokenRefreshModule.getRefreshedToken()).rejects.toThrow(
        "No refresh token",
      );
      expect(mockStoreDispatch).toHaveBeenCalledWith({ type: "LOGOUT" });
      expect(mockLogout).toHaveBeenCalled();
      expect(fetchStub).not.toHaveBeenCalled();
    });

    /**
     * @description Should logout and throw when API response is not ok
     * @scenario fetch returns ok: false
     * @expected throws 'Refresh failed', dispatch logout action
     */
    it('should throw "Refresh failed" and logout when API response is not ok', async () => {
      // Arrange
      mockGetRefreshToken.mockReturnValue("valid-refresh");
      fetchStub.mockResolvedValue({
        ok: false,
        json: vi.fn(),
      });

      // Act & Assert
      await expect(tokenRefreshModule.getRefreshedToken()).rejects.toThrow(
        "Refresh failed",
      );
      expect(mockStoreDispatch).toHaveBeenCalledWith({ type: "LOGOUT" });
      expect(mockLogout).toHaveBeenCalled();
    });

    /**
     * @description Should logout and throw when fetch itself rejects
     * @scenario fetch promise rejects with network error
     * @expected the same error is thrown, dispatch logout action
     */
    it('should throw "Network error" and logout when fetch fails', async () => {
      // Arrange
      const networkError = new Error("Network error");
      mockGetRefreshToken.mockReturnValue("valid-refresh");
      fetchStub.mockRejectedValue(networkError);

      // Act & Assert
      await expect(tokenRefreshModule.getRefreshedToken()).rejects.toThrow(
        "Network error",
      );
      expect(mockStoreDispatch).toHaveBeenCalledWith({ type: "LOGOUT" });
      expect(mockLogout).toHaveBeenCalled();
    });
  });
});
