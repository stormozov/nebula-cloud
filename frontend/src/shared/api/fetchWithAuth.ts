import { getAccessTokenFromPersist } from "../utils/getPersistedAuthState";
import { getRefreshedToken } from "./tokenRefresh";

/**
 * Global authenticated fetch with 401 auto-logout.
 *
 * Used for direct fetch calls (download, preview) that bypass RTK Query.
 * If a 401 occurs, dispatches logout and throws the Response object.
 */
export const fetchWithAuth = async (
  input: RequestInfo | URL,
  init?: RequestInit,
  retry = true,
): Promise<Response> => {
  const token = getAccessTokenFromPersist();
  const headers = new Headers(init?.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response = await fetch(input, { ...init, headers });

  if (response.status === 401 && retry) {
    try {
      const newToken = await getRefreshedToken();
      headers.set("Authorization", `Bearer ${newToken}`);
      response = await fetch(input, { ...init, headers });
    } catch {
      const { logout } = await import("@/entities/user");
      const { store } = await import("@/app/store/store");
      store.dispatch(logout());
      throw response;
    }
  }

  return response;
};
