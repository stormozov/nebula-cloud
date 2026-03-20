import { useEffect } from "react";
import { useStore } from "react-redux";

import { logout } from "@/entities/user";
import { getAccessTokenFromPersist } from "@/shared/utils/getPersistedAuthState";
import { isTokenExpired } from "@/shared/utils/isTokenExpired";

/**
 * Custom React hook that handles token validation and automatic logout
 * when the access token has expired.
 *
 * When an expired token is detected, the hook removes the persisted auth data
 * from localStorage and dispatches a logout action to update the app state.
 *
 * This hook performs the following:
 * - Validates the stored access token on mount
 * - Sets up periodic validation every 5 minutes
 * - Validates the token whenever the window gains focus
 * - Clears the auth persistence and logs out the user if the token is expired
 *
 * @remarks
 * The token validation occurs:
 * - Immediately when the hook mounts
 * - Every 5 minutes via setInterval
 * - Whenever the browser window/tab regains focus
 */
export const useTokenValidation = (): void => {
  const store = useStore();

  useEffect(() => {
    const validateToken = () => {
      const token = getAccessTokenFromPersist();
      if (token && isTokenExpired(token)) {
        localStorage.removeItem("persist:auth");
        store.dispatch(logout());
      }
    };

    validateToken();

    const interval = setInterval(validateToken, 5 * 60 * 1000); // 5 min
    window.addEventListener("focus", validateToken);

    return () => {
      clearInterval(interval);
      window.removeEventListener("focus", validateToken);
    };
  }, [store]);
};
