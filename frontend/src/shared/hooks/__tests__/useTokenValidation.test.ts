import { act, renderHook } from "@testing-library/react";
import { useStore } from "react-redux";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  vi,
} from "vitest";

import { useAppSelector } from "@/app/store/hooks";
import { logout } from "@/entities/user";
import {
  selectAccessToken,
  selectRefreshToken,
} from "@/entities/user/model/selectors";
import * as tokenUtils from "@/shared/utils";

import * as api from "../../api";
import { useTokenValidation } from "../useTokenValidation";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("react-redux", () => ({
  useStore: vi.fn(),
}));

vi.mock("@/app/store/hooks", () => ({
  useAppSelector: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  logout: vi.fn(),
}));

vi.mock("@/shared/utils", () => ({
  getTokenExpirationTime: vi.fn(),
  isTokenExpired: vi.fn(),
}));

vi.mock("../../api", () => ({
  getRefreshedToken: vi.fn(),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("useTokenValidation", () => {
  const dispatchMock = vi.fn();
  const storeMock = { dispatch: dispatchMock };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    (useStore as unknown as Mock).mockReturnValue(storeMock);
    // Default: both tokens undefined
    (useAppSelector as Mock).mockReturnValue(undefined);
    // Make logout return a predictable action object
    (logout as unknown as Mock).mockReturnValue({ type: "logout" });
    // isTokenExpired defaults to false
    (tokenUtils.isTokenExpired as Mock).mockReturnValue(false);
    // getTokenExpirationTime defaults to a far future
    (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(
      Date.now() + 600_000,
    );
    // getRefreshedToken defaults to resolved promise
    (api.getRefreshedToken as Mock).mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const setTokens = (
    accessToken: string | undefined,
    refreshToken: string | undefined,
  ) => {
    (useAppSelector as Mock).mockImplementation((selector: unknown) => {
      if (selector === selectAccessToken) return accessToken;
      if (selector === selectRefreshToken) return refreshToken;
      return undefined;
    });
  };

  describe("when refreshToken is absent", () => {
    /**
     * @description Should dispatch logout when refreshToken is undefined
     * @scenario useAppSelector returns undefined for refreshToken
     * @expected store.dispatch is called with logout() action
     */
    it("should dispatch logout when refreshToken is undefined", () => {
      // Arrange
      setTokens("valid_access", undefined);

      // Act
      renderHook(() => useTokenValidation());

      // Assert
      expect(dispatchMock).toHaveBeenCalledWith(logout());
    });

    /**
     * @description Should dispatch logout when refreshToken is null
     * @scenario useAppSelector returns null for refreshToken
     * @expected store.dispatch is called with logout() action
     */
    it("should dispatch logout when refreshToken is null", () => {
      // Arrange
      setTokens("valid_access", null as unknown as undefined);

      // Act
      renderHook(() => useTokenValidation());

      // Assert
      expect(dispatchMock).toHaveBeenCalledWith(logout());
    });
  });

  describe("when refreshToken is expired", () => {
    /**
     * @description Should dispatch logout when refreshToken is present but expired
     * @scenario isTokenExpired(refreshToken) returns true
     * @expected store.dispatch is called with logout() action
     */
    it("should dispatch logout when refreshToken is expired", () => {
      // Arrange
      setTokens("valid_access", "expired_refresh");
      (tokenUtils.isTokenExpired as Mock).mockReturnValue(true);

      // Act
      renderHook(() => useTokenValidation());

      // Assert
      expect(dispatchMock).toHaveBeenCalledWith(logout());
      expect(tokenUtils.isTokenExpired).toHaveBeenCalledWith("expired_refresh");
    });
  });

  describe("when refreshToken is valid but accessToken is absent", () => {
    /**
     * @description Should do nothing when accessToken is undefined
     * @scenario refreshToken is valid, accessToken not present
     * @expected No dispatch, no timer, no API call
     */
    it("should not call any side effects when accessToken is undefined", () => {
      // Arrange
      setTokens(undefined, "valid_refresh");

      // Act
      renderHook(() => useTokenValidation());

      // Assert
      expect(dispatchMock).not.toHaveBeenCalled();
      expect(api.getRefreshedToken).not.toHaveBeenCalled();
    });
  });

  describe("when accessToken has no expiration time", () => {
    /**
     * @description Should return early when getTokenExpirationTime returns undefined
     * @scenario getTokenExpirationTime returns undefined
     * @expected No dispatch, no timer
     */
    it("should return early when getTokenExpirationTime returns falsy", () => {
      // Arrange
      setTokens("access_no_exp", "valid_refresh");
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(undefined);

      // Act
      renderHook(() => useTokenValidation());

      // Assert
      expect(dispatchMock).not.toHaveBeenCalled();
      expect(api.getRefreshedToken).not.toHaveBeenCalled();
    });
  });

  describe("when accessToken is close to expiry", () => {
    /**
     * @description Should call getRefreshedToken immediately when exp is within threshold
     * @scenario timeUntilExp <= 60000, getRefreshedToken resolves
     * @expected getRefreshedToken is called, no logout
     */
    it("should refresh token when exp is within threshold", async () => {
      // Arrange
      setTokens("access_about_to_expire", "valid_refresh");
      const expTime = Date.now() + 30000; // 30 seconds until expiry
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(expTime);

      // Act
      renderHook(() => useTokenValidation());
      // Since it's immediate, we just need to flush promises
      await vi.runAllTimersAsync();

      // Assert
      expect(api.getRefreshedToken).toHaveBeenCalledTimes(1);
      expect(dispatchMock).not.toHaveBeenCalled();
    });

    /**
     * @description Should dispatch logout when immediate refresh fails
     * @scenario timeUntilExp <= 60000, getRefreshedToken rejects
     * @expected logout is dispatched
     */
    it("should dispatch logout when immediate refresh fails", async () => {
      // Arrange
      setTokens("access_about_to_expire", "valid_refresh");
      const expTime = Date.now() + 30_000;
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(expTime);
      (api.getRefreshedToken as Mock).mockRejectedValue(new Error("failed"));

      // Act
      renderHook(() => useTokenValidation());
      await vi.runAllTimersAsync();

      // Assert
      expect(api.getRefreshedToken).toHaveBeenCalledTimes(1);
      expect(dispatchMock).toHaveBeenCalledWith(logout());
    });
  });

  describe("when accessToken is far from expiry", () => {
    /**
     * @description Should set a timeout that calls getRefreshedToken after delay
     * @scenario timeUntilExp - threshold = delay, after delay getRefreshedToken called
     * @expected getRefreshedToken is called after advancing time, no logout on success
     */
    it("should schedule refresh after delay", async () => {
      // Arrange
      setTokens("access_long_exp", "valid_refresh");
      const expTime = Date.now() + 120_000; // 2 minutes
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(expTime);

      // Act
      renderHook(() => useTokenValidation());
      // token not refreshed immediately
      expect(api.getRefreshedToken).not.toHaveBeenCalled();

      // Advance time by (120_000 - 60_000) = 60_000 ms
      await act(() => vi.advanceTimersByTimeAsync(60000));

      // Assert
      expect(api.getRefreshedToken).toHaveBeenCalledTimes(1);
      expect(dispatchMock).not.toHaveBeenCalled();
    });

    /**
     * @description Should clear timeout when component unmounts before scheduled refresh
     * @scenario Hook mounts, then unmounts before the scheduled timeout
     * @expected getRefreshedToken is never called
     */
    it("should clear timeout on unmount", () => {
      // Arrange
      setTokens("access_long_exp", "valid_refresh");
      const expTime = Date.now() + 120_000;
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(expTime);

      // Act
      const { unmount } = renderHook(() => useTokenValidation());
      unmount();
      vi.advanceTimersByTime(60_000);

      // Assert
      expect(api.getRefreshedToken).not.toHaveBeenCalled();
    });

    /**
     * @description Should dispatch logout when scheduled refresh fails
     * @scenario Timeout fires, getRefreshedToken rejects
     * @expected logout is dispatched after failure
     */
    it("should dispatch logout when scheduled refresh fails", async () => {
      // Arrange
      setTokens("access_long_exp", "valid_refresh");
      const expTime = Date.now() + 120_000;
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(expTime);
      (api.getRefreshedToken as Mock).mockRejectedValue(new Error("fail"));

      // Act
      renderHook(() => useTokenValidation());
      await act(() => vi.advanceTimersByTimeAsync(60_000));

      // Assert
      expect(api.getRefreshedToken).toHaveBeenCalledTimes(1);
      expect(dispatchMock).toHaveBeenCalledWith(logout());
    });
  });

  describe("when dependencies change", () => {
    /**
     * @description Should cleanup old timeout and set new one when tokens change
     * @scenario accessToken changes causing effect to re-run
     * @expected old timeout cleared, new timeout set with new expiration
     */
    it("should reset timeout on token change", async () => {
      // Arrange
      setTokens("token_v1", "valid_refresh");
      const firstExpTime = Date.now() + 120_000;
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(firstExpTime);

      const { rerender } = renderHook(() => useTokenValidation());
      expect(api.getRefreshedToken).not.toHaveBeenCalled();

      // Change token
      setTokens("token_v2", "valid_refresh");
      const secondExpTime = Date.now() + 200_000; // new exp later
      (tokenUtils.getTokenExpirationTime as Mock).mockReturnValue(
        secondExpTime,
      );

      // Act: rerender with new values
      rerender();

      // The old timeout should be cleared; advance time by old delay should not trigger refresh
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      expect(api.getRefreshedToken).not.toHaveBeenCalled(); // old timeout cleared

      // Advance further to new delay (200_000 - 60_000 = 140_000), but we've already advanced 60000, so need 80000 more
      await act(() => vi.advanceTimersByTimeAsync(80_000));
      expect(api.getRefreshedToken).toHaveBeenCalledTimes(1);
    });
  });
});
