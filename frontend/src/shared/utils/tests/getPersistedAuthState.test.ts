import { describe, expect, it, vi } from "vitest";

import {
  getAccessTokenFromPersist,
  getPersistedAuthState,
  getRefreshTokenFromPersist,
} from "../getPersistedAuthState";

describe("getPersistedAuthState", () => {
  describe("No persisted auth state in localStorage", () => {
    /**
     * @description Should return null when localStorage has no persisted auth data
     * @scenario localStorage.getItem returns null for "persist:auth" key
     * @expected Returns null
     */
    it("should return null when persist key does not exist", () => {
      vi.spyOn(localStorage, "getItem").mockReturnValue(null);
      expect(getPersistedAuthState()).toBeNull();
    });

    /**
     * @description Should return null when localStorage returns empty string
     * @scenario localStorage.getItem returns empty string for "persist:auth" key
     * @expected Returns null due to empty string being falsy
     */
    it("should return null for empty string persisted data", () => {
      vi.spyOn(localStorage, "getItem").mockReturnValue("");
      expect(getPersistedAuthState()).toBeNull();
    });
  });

  describe("Malformed persisted data", () => {
    /**
     * @description Should return null when persisted data is not valid JSON
     * @scenario localStorage returns invalid JSON string
     * @expected Returns null due to JSON parse error
     */
    it("should return null for invalid JSON string", () => {
      vi.spyOn(localStorage, "getItem").mockReturnValue("not-valid-json");
      expect(getPersistedAuthState()).toBeNull();
    });

    /**
     * @description Should return null when persisted data causes JSON parse error
     * @scenario Top-level JSON.parse throws an error
     * @expected Returns null due to catch block
     */
    it("should return null when top-level JSON parsing fails", () => {
      vi.spyOn(localStorage, "getItem").mockReturnValue("{invalid}");
      expect(getPersistedAuthState()).toBeNull();
    });
  });

  describe("Persisted data with missing or null fields", () => {
    /**
     * @description Should return null values for all fields when persisted data is empty object
     * @scenario localStorage returns valid JSON but with no auth fields
     * @expected Returns object with all null/false values
     */
    it("should return null values for empty persisted object", () => {
      vi.spyOn(localStorage, "getItem").mockReturnValue("{}");
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: null,
        refreshToken: null,
        isAuthenticated: false,
      });
    });

    /**
     * @description Should handle persisted data with only isAuthenticated field
     * @scenario Only isAuthenticated field present in persisted data
     * @expected Returns null for tokens, parsed boolean for isAuthenticated
     */
    it("should handle persisted data with only isAuthenticated field", () => {
      const persisted = JSON.stringify({
        isAuthenticated: JSON.stringify(true),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: null,
        refreshToken: null,
        isAuthenticated: true,
      });
    });

    /**
     * @description Should return null values when fields are explicitly null
     * @scenario Fields present but set to null in persisted data
     * @expected Returns null for tokens, false for isAuthenticated
     */
    it("should return null values when fields are null", () => {
      const persisted = JSON.stringify({
        accessToken: null,
        refreshToken: null,
        isAuthenticated: null,
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: null,
        refreshToken: null,
        isAuthenticated: false,
      });
    });
  });

  describe("Valid persisted auth state", () => {
    /**
     * @description Should correctly parse all auth state fields
     * @scenario localStorage contains valid persisted auth state with all fields
     * @expected Returns object with parsed accessToken, refreshToken, and isAuthenticated
     */
    it("should correctly parse all auth state fields", () => {
      const persisted = JSON.stringify({
        accessToken: JSON.stringify("mock-access-token"),
        refreshToken: JSON.stringify("mock-refresh-token"),
        isAuthenticated: JSON.stringify(true),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: "mock-access-token",
        refreshToken: "mock-refresh-token",
        isAuthenticated: true,
      });
    });

    /**
     * @description Should handle isAuthenticated as false string
     * @scenario isAuthenticated field contains string "false"
     * @expected Returns false boolean
     */
    it("should handle isAuthenticated as false string", () => {
      const persisted = JSON.stringify({
        accessToken: JSON.stringify("mock-access-token"),
        refreshToken: JSON.stringify("mock-refresh-token"),
        isAuthenticated: JSON.stringify(false),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: "mock-access-token",
        refreshToken: "mock-refresh-token",
        isAuthenticated: false,
      });
    });

    /**
     * @description Should return null when any nested field has invalid JSON
     * @scenario accessToken field contains invalid JSON but other fields are valid
     * @expected Returns null due to catch block catching the parse error
     */
    it("should return null when nested JSON parsing fails for accessToken", () => {
      const persisted = JSON.stringify({
        accessToken: "invalid-json",
        refreshToken: JSON.stringify("mock-refresh-token"),
        isAuthenticated: JSON.stringify(true),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      expect(getPersistedAuthState()).toBeNull();
    });

    /**
     * @description Should return null when refreshToken field has invalid JSON
     * @scenario refreshToken field contains invalid JSON but other fields are valid
     * @expected Returns null due to catch block catching the parse error
     */
    it("should return null when nested JSON parsing fails for refreshToken", () => {
      const persisted = JSON.stringify({
        accessToken: JSON.stringify("mock-access-token"),
        refreshToken: "invalid-json",
        isAuthenticated: JSON.stringify(true),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      expect(getPersistedAuthState()).toBeNull();
    });

    /**
     * @description Should return null when isAuthenticated field has invalid JSON
     * @scenario isAuthenticated field contains invalid JSON but other fields are valid
     * @expected Returns null due to catch block catching the parse error
     */
    it("should return null when nested JSON parsing fails for isAuthenticated", () => {
      const persisted = JSON.stringify({
        accessToken: JSON.stringify("mock-access-token"),
        refreshToken: JSON.stringify("mock-refresh-token"),
        isAuthenticated: "invalid-json",
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      expect(getPersistedAuthState()).toBeNull();
    });

    /**
     * @description Should handle empty string values for token fields
     * @scenario Token fields contain empty strings instead of JSON
     * @expected Returns null for empty string tokens (falsy check)
     */
    it("should handle empty string values for token fields", () => {
      const persisted = JSON.stringify({
        accessToken: "",
        refreshToken: "",
        isAuthenticated: JSON.stringify(true),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: null,
        refreshToken: null,
        isAuthenticated: true,
      });
    });

    /**
     * @description Should handle complex token strings with special characters
     * @scenario Tokens contain complex JWT-like strings
     * @expected Returns the exact token strings
     */
    it("should handle complex token strings with special characters", () => {
      const complexToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
      const persisted = JSON.stringify({
        accessToken: JSON.stringify(complexToken),
        refreshToken: JSON.stringify(complexToken),
        isAuthenticated: JSON.stringify(true),
      });
      vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
      const result = getPersistedAuthState();
      expect(result).toEqual({
        accessToken: complexToken,
        refreshToken: complexToken,
        isAuthenticated: true,
      });
    });
  });
});

describe("getRefreshTokenFromPersist", () => {
  /**
   * @description Should return undefined when no persisted auth state
   * @scenario localStorage returns null for persisted auth
   * @expected Returns undefined
   */
  it("should return undefined when no persisted auth state", () => {
    vi.spyOn(localStorage, "getItem").mockReturnValue(null);
    expect(getRefreshTokenFromPersist()).toBeUndefined();
  });

  /**
   * @description Should return undefined when refreshToken is null
   * @scenario Persisted state exists but refreshToken is null
   * @expected Returns undefined
   */
  it("should return undefined when refreshToken is null", () => {
    const persisted = JSON.stringify({
      accessToken: JSON.stringify("mock-access-token"),
      refreshToken: null,
      isAuthenticated: JSON.stringify(true),
    });
    vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
    expect(getRefreshTokenFromPersist()).toBeUndefined();
  });

  /**
   * @description Should return refreshToken string when present
   * @scenario Persisted state contains valid refreshToken
   * @expected Returns the refreshToken string
   */
  it("should return refreshToken string when present", () => {
    const persisted = JSON.stringify({
      accessToken: JSON.stringify("mock-access-token"),
      refreshToken: JSON.stringify("mock-refresh-token"),
      isAuthenticated: JSON.stringify(true),
    });
    vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
    expect(getRefreshTokenFromPersist()).toBe("mock-refresh-token");
  });
});

describe("getAccessTokenFromPersist", () => {
  /**
   * @description Should return null when no persisted auth state
   * @scenario localStorage returns null for persisted auth
   * @expected Returns null
   */
  it("should return null when no persisted auth state", () => {
    vi.spyOn(localStorage, "getItem").mockReturnValue(null);
    expect(getAccessTokenFromPersist()).toBeNull();
  });

  /**
   * @description Should return null when accessToken is null
   * @scenario Persisted state exists but accessToken is null
   * @expected Returns null
   */
  it("should return null when accessToken is null", () => {
    const persisted = JSON.stringify({
      accessToken: null,
      refreshToken: JSON.stringify("mock-refresh-token"),
      isAuthenticated: JSON.stringify(true),
    });
    vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
    expect(getAccessTokenFromPersist()).toBeNull();
  });

  /**
   * @description Should return accessToken string when present
   * @scenario Persisted state contains valid accessToken
   * @expected Returns the accessToken string
   */
  it("should return accessToken string when present", () => {
    const persisted = JSON.stringify({
      accessToken: JSON.stringify("mock-access-token"),
      refreshToken: JSON.stringify("mock-refresh-token"),
      isAuthenticated: JSON.stringify(true),
    });
    vi.spyOn(localStorage, "getItem").mockReturnValue(persisted);
    expect(getAccessTokenFromPersist()).toBe("mock-access-token");
  });
});
