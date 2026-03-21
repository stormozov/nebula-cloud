import { logout, setTokens } from "@/entities/user";

import { getRefreshTokenFromPersist } from "../utils";
import { API_BASE_URL } from "./apiBaseUrl";

let isRefreshing = false;
let refreshSubscribers: ((token: string) => void)[] = [];

/**
 * Update the token and notifies all pending requests.
 */
const refreshToken = async (): Promise<string> => {
  const refreshTokenValue = getRefreshTokenFromPersist();
  if (!refreshTokenValue) throw new Error("No refresh token");

  const response = await fetch(`${API_BASE_URL}/auth/refresh/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh: refreshTokenValue }),
  });

  if (!response.ok) throw new Error("Refresh failed");

  const { store } = await import("@/app/store/store");
  const data = await response.json();
  const { access, refresh } = data;

  store.dispatch(setTokens({ access, refresh }));
  localStorage.setItem(
    "persist:auth",
    JSON.stringify({
      accessToken: JSON.stringify(access),
      refreshToken: JSON.stringify(refresh),
    }),
  );

  return access;
};

/**
 * Adds a callback to the waiting update queue.
 */
const subscribeTokenRefresh = (callback: (token: string) => void) => {
  refreshSubscribers.push(callback);
};

/**
 * Notifies all pending requests about the new token.
 */
const onRefreshed = (token: string) => {
  refreshSubscribers.forEach((cb) => {
    cb(token);
  });
  refreshSubscribers = [];
};

/**
 * Retrieves a refreshed authentication token, ensuring that only one refresh
 * operation is active at a time to prevent multiple concurrent token refresh
 * requests.
 *
 * @returns A promise that resolves to the newly refreshed authentication token.
 *
 * @throws Propagates any error that occurs during the token refresh process
 * after logging out the user.
 *
 * @example
 * ```ts
 * try {
 *   const token = await getRefreshedToken();
 *   setAuthToken(token);
 * } catch (error) {
 *   console.error("Failed to refresh token:", error);
 * }
 * ```
 */
export const getRefreshedToken = async (): Promise<string> => {
  if (!isRefreshing) {
    isRefreshing = true;
    try {
      const newToken = await refreshToken();
      onRefreshed(newToken);
      return newToken;
    } catch (error) {
      const { store } = await import("@/app/store/store");
      store.dispatch(logout());
      throw error;
    } finally {
      isRefreshing = false;
    }
  } else {
    return new Promise((resolve) => {
      subscribeTokenRefresh(resolve);
    });
  }
};
