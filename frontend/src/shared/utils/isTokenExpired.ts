/**
 * Safely decodes JWT token payload and checks if expired.
 *
 * No signature verification - only trusts exp claim.
 */
export const isTokenExpired = (token: string | null): boolean => {
  if (!token) return true;

  try {
    // JWT format: header.payload.signature
    const payload = token.split(".")[1];
    const decoded = JSON.parse(atob(payload));
    const exp = decoded.exp * 1000; // JWT exp in seconds → ms
    return Date.now() >= exp;
  } catch {
    // Invalid token → expired
    return true;
  }
};
