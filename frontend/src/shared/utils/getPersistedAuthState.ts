/**
 * Persisted auth state properties.
 */
interface IPersistedAuthStateProps {
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
}

/**
 * Reads the persisted auth state from localStorage.
 *
 * Used for accessing tokens in API layer without importing Redux types.
 *
 * @returns Parsed auth state or null if not found
 */
export const getPersistedAuthState = (): IPersistedAuthStateProps | null => {
  try {
    const persisted = localStorage.getItem("persist:auth");
    if (!persisted) return null;

    const parsed = JSON.parse(persisted) as Record<string, string>;

    return {
      accessToken: parsed.accessToken ? JSON.parse(parsed.accessToken) : null,
      refreshToken: parsed.refreshToken
        ? JSON.parse(parsed.refreshToken)
        : null,
      isAuthenticated: parsed.isAuthenticated
        ? JSON.parse(parsed.isAuthenticated)
        : false,
    };
  } catch {
    return null;
  }
};

/**
 * Gets refresh token from persisted auth state.
 *
 * Helper for API calls that need the token.
 */
export const getRefreshTokenFromPersist = (): string | undefined => {
  const state = getPersistedAuthState();
  return state?.refreshToken || undefined;
};

/**
 * Gets access token from persisted auth state.
 *
 * Helper for API headers.
 */
export const getAccessTokenFromPersist = (): string | null => {
  const state = getPersistedAuthState();
  return state?.accessToken || null;
};
