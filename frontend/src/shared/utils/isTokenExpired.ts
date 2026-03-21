/**
 * Extracts and returns the expiration time of a JWT token in milliseconds.
 *
 * Parses the payload (second part) of a JWT token, decodes it from base64,
 * and retrieves the `exp` claim, which represents the expiration time as a Unix
 * timestamp in seconds.
 *
 * @param token - The JWT token string (in format `header.payload.signature`).
 * @returns The expiration time in milliseconds since Unix epoch, or `null`
 * if the token is invalid or has no `exp` claim.
 *
 * @example
 * const expTime = getTokenExpirationTime(token);
 * if (expTime && Date.now() < expTime) {
 *   console.log("Token is still valid");
 * }
 */
export const getTokenExpirationTime = (token: string): number | null => {
  try {
    const payload = token.split(".")[1];
    const decoded = JSON.parse(atob(payload));
    return decoded.exp ? decoded.exp * 1000 : null;
  } catch {
    return null;
  }
};

/**
 * Checks whether a JWT token is expired or not.
 *
 * Uses the current time and compares it with the token's expiration time.
 * Returns `true` if the token is expired or invalid.
 *
 * @param token - The JWT token string or `null`.
 * @returns `true` if the token is expired or invalid; `false` otherwise.
 *
 * @example
 * if (isTokenExpired(accessToken)) {
 *   // Token needs refresh
 * }
 */
export const isTokenExpired = (token: string | null): boolean => {
  if (!token) return true;
  const exp = getTokenExpirationTime(token);
  if (!exp) return true;
  return Date.now() >= exp;
};