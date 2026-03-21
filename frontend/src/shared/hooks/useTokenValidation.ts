import { useEffect } from "react";
import { useStore } from "react-redux";

import { useAppSelector } from "@/app/store/hooks";
import { logout } from "@/entities/user";
import {
  selectAccessToken,
  selectRefreshToken,
} from "@/entities/user/model/selectors";
import { getTokenExpirationTime, isTokenExpired } from "@/shared/utils";

import { getRefreshedToken } from "../api";

/**
 * Custom hook that handles automatic token validation and refresh.
 *
 * Monitors the access and refresh tokens stored in Redux. If the access token
 * is about to expire, it automatically requests a new one using the refresh
 * token. If the refresh token is missing or expired, the user is logged out.
 *
 * This hook should be used at a high level in the app (e.g., App component)
 * to ensure continuous authentication state management.
 */
export const useTokenValidation = (): void => {
  const store = useStore();
  const accessToken = useAppSelector(selectAccessToken);
  const refreshToken = useAppSelector(selectRefreshToken);

  useEffect(() => {
    // If there is no refresh token or it has expired, log out
    if (!refreshToken || isTokenExpired(refreshToken)) {
      store.dispatch(logout());
      return;
    }

    // If there is no access token, do nothing
    if (!accessToken) return;

    const expMs = getTokenExpirationTime(accessToken);
    if (!expMs) return;

    const now = Date.now();
    const timeUntilExp = expMs - now;
    const refreshThreshold = 60 * 1000;

    // If the token has already expired or is about to expire, update it
    if (timeUntilExp <= refreshThreshold) {
      getRefreshedToken().catch(() => store.dispatch(logout()));
      return;
    }

    // Otherwise, set a timer to update the refreshThreshold before it expires
    const timeoutId = setTimeout(() => {
      getRefreshedToken().catch(() => store.dispatch(logout()));
    }, timeUntilExp - refreshThreshold);

    return () => clearTimeout(timeoutId);
  }, [accessToken, refreshToken, store]);
};
