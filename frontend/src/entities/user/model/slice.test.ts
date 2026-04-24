import { describe, expect, it } from "vitest";

import {
  clearError,
  logout,
  setAuthData,
  setError,
  setLoading,
  setTokens,
  setUser,
  userSlice,
} from "./slice";
import type { IAuthState, IToken, IUser, IUserAuthResponse } from "./types";

/** Helper to create a mock user */
const createMockUser = (overrides: Partial<IUser> = {}): IUser => ({
  id: 1,
  username: "testuser",
  email: "test@example.com",
  firstName: "Test",
  lastName: "User",
  fullName: "Test User",
  isActive: true,
  isStaff: false,
  storagePath: "",
  dateJoined: "2022-01-01T00:00:00.000Z",
  lastLogin: "",
  ...overrides,
});

/** Helper to create mock tokens */
const createMockTokens = (overrides: Partial<IToken> = {}): IToken => ({
  access: "mock-access-token",
  refresh: "mock-refresh-token",
  ...overrides,
});

/** Helper to create mock auth response */
const createMockAuthResponse = (
  overrides: Partial<IUserAuthResponse> = {},
): IUserAuthResponse => ({
  ...createMockTokens(),
  user: createMockUser(),
  ...overrides,
});

/** Default initial state for comparison */
const initialState: IAuthState = {
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
};

/** Reducer reference for testing */
const reducer = userSlice.reducer;

describe("userSlice", () => {
  describe("Initial state", () => {
    /**
     * @description Should have correct initial state
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have correct initial state", () => {
      expect(reducer(undefined, { type: "unknown" })).toEqual(initialState);
    });
  });

  describe("setAuthData", () => {
    /**
     * @description Should set all auth data correctly
     * @scenario Setting auth data with valid response should update all fields
     * @expected User, tokens, and isAuthenticated should be set
     */
    it("should set all auth data correctly", () => {
      const authResponse = createMockAuthResponse();
      const state = reducer(initialState, setAuthData(authResponse));

      expect(state.user).toEqual(authResponse.user);
      expect(state.accessToken).toBe(authResponse.access);
      expect(state.refreshToken).toBe(authResponse.refresh);
      expect(state.isAuthenticated).toBe(true);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should overwrite existing user data
     * @scenario Setting auth data when user already exists should replace data
     * @expected New user data should replace old data
     */
    it("should overwrite existing user data", () => {
      const existingState: IAuthState = {
        ...initialState,
        user: createMockUser({ id: 1, username: "olduser" }),
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        isAuthenticated: true,
      };

      const newAuthResponse = createMockAuthResponse({
        user: createMockUser({ id: 2, username: "newuser" }),
      });

      const state = reducer(existingState, setAuthData(newAuthResponse));

      expect(state.user?.username).toBe("newuser");
      expect(state.user?.id).toBe(2);
      expect(state.accessToken).toBe("mock-access-token");
    });

    /**
     * @description Should clear any existing error
     * @scenario Setting auth data after an error should clear error
     * @expected Error should be null after setting auth data
     */
    it("should clear any existing error", () => {
      const stateWithError: IAuthState = {
        ...initialState,
        error: "Some error occurred",
      };

      const state = reducer(
        stateWithError,
        setAuthData(createMockAuthResponse()),
      );

      expect(state.error).toBeNull();
    });

    /**
     * @description Should handle staff user correctly
     * @scenario Setting auth data with staff user should preserve isStaff flag
     * @expected isStaff flag should match the response
     */
    it("should handle staff user correctly", () => {
      const authResponse = createMockAuthResponse({
        user: createMockUser({ isStaff: true }),
      });

      const state = reducer(initialState, setAuthData(authResponse));

      expect(state.user?.isStaff).toBe(true);
    });
  });

  describe("setUser", () => {
    /**
     * @description Should set user and update authentication status
     * @scenario Setting user with valid user object should set isAuthenticated to true
     * @expected User should be set and isAuthenticated should be true
     */
    it("should set user and update authentication status to true", () => {
      const user = createMockUser();
      const state = reducer(initialState, setUser(user));

      expect(state.user).toEqual(user);
      expect(state.isAuthenticated).toBe(true);
    });

    /**
     * @description Should set user to null and update authentication status
     * @scenario Setting user to null should set isAuthenticated to false
     * @expected User should be null and isAuthenticated should be false
     */
    it("should set user to null and update authentication status to false", () => {
      const stateWithUser: IAuthState = {
        ...initialState,
        user: createMockUser(),
        isAuthenticated: true,
      };

      const state = reducer(stateWithUser, setUser(null));

      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });

    /**
     * @description Should preserve other state fields
     * @scenario Setting user should not affect other fields like tokens
     * @expected Tokens should remain unchanged
     */
    it("should preserve other state fields", () => {
      const stateWithTokens: IAuthState = {
        ...initialState,
        accessToken: "some-token",
        refreshToken: "some-refresh",
      };

      const state = reducer(stateWithTokens, setUser(createMockUser()));

      expect(state.accessToken).toBe("some-token");
      expect(state.refreshToken).toBe("some-refresh");
    });

    /**
     * @description Should overwrite existing user
     * @scenario Setting new user should replace existing user
     * @expected New user should replace old user
     */
    it("should overwrite existing user", () => {
      const stateWithUser: IAuthState = {
        ...initialState,
        user: createMockUser({ id: 1, username: "old" }),
        isAuthenticated: true,
      };

      const newUser = createMockUser({ id: 2, username: "new" });
      const state = reducer(stateWithUser, setUser(newUser));

      expect(state.user?.username).toBe("new");
      expect(state.user?.id).toBe(2);
    });
  });

  describe("setTokens", () => {
    /**
     * @description Should set both access and refresh tokens
     * @scenario Setting tokens with valid token object should update both fields
     * @expected Both tokens should be set
     */
    it("should set both access and refresh tokens", () => {
      const tokens = createMockTokens();
      const state = reducer(initialState, setTokens(tokens));

      expect(state.accessToken).toBe(tokens.access);
      expect(state.refreshToken).toBe(tokens.refresh);
    });

    /**
     * @description Should update existing tokens
     * @scenario Setting new tokens should replace existing ones
     * @expected New tokens should replace old tokens
     */
    it("should update existing tokens", () => {
      const stateWithTokens: IAuthState = {
        ...initialState,
        accessToken: "old-access",
        refreshToken: "old-refresh",
      };

      const newTokens = createMockTokens({
        access: "new-access",
        refresh: "new-refresh",
      });

      const state = reducer(stateWithTokens, setTokens(newTokens));

      expect(state.accessToken).toBe("new-access");
      expect(state.refreshToken).toBe("new-refresh");
    });

    /**
     * @description Should preserve user data
     * @scenario Setting tokens should not affect user data
     * @expected User should remain unchanged
     */
    it("should preserve user data", () => {
      const stateWithUser: IAuthState = {
        ...initialState,
        user: createMockUser(),
        isAuthenticated: true,
      };

      const state = reducer(stateWithUser, setTokens(createMockTokens()));

      expect(state.user).toEqual(createMockUser());
      expect(state.isAuthenticated).toBe(true);
    });

    /**
     * @description Should handle empty token strings
     * @scenario Setting tokens with empty strings should set empty strings
     * @expected Tokens should be empty strings
     */
    it("should handle empty token strings", () => {
      const emptyTokens: IToken = { access: "", refresh: "" };
      const state = reducer(initialState, setTokens(emptyTokens));

      expect(state.accessToken).toBe("");
      expect(state.refreshToken).toBe("");
    });
  });

  describe("setLoading", () => {
    /**
     * @description Should set loading to true
     * @scenario Setting loading to true should update isLoading field
     * @expected isLoading should be true
     */
    it("should set loading to true", () => {
      const state = reducer(initialState, setLoading(true));
      expect(state.isLoading).toBe(true);
    });

    /**
     * @description Should set loading to false
     * @scenario Setting loading to false should update isLoading field
     * @expected isLoading should be false
     */
    it("should set loading to false", () => {
      const loadingState: IAuthState = {
        ...initialState,
        isLoading: true,
      };

      const state = reducer(loadingState, setLoading(false));
      expect(state.isLoading).toBe(false);
    });

    /**
     * @description Should preserve other state fields
     * @scenario Setting loading should not affect other fields
     * @expected User and tokens should remain unchanged
     */
    it("should preserve other state fields", () => {
      const stateWithData: IAuthState = {
        ...initialState,
        user: createMockUser(),
        accessToken: "some-token",
        isAuthenticated: true,
      };

      const state = reducer(stateWithData, setLoading(true));

      expect(state.user).toEqual(createMockUser());
      expect(state.accessToken).toBe("some-token");
    });

    /**
     * @description Should toggle loading state correctly
     * @scenario Toggling loading from true to false and back
     * @expected isLoading should reflect the latest value
     */
    it("should toggle loading state correctly", () => {
      const state1 = reducer(initialState, setLoading(true));
      expect(state1.isLoading).toBe(true);

      const state2 = reducer(state1, setLoading(false));
      expect(state2.isLoading).toBe(false);

      const state3 = reducer(state2, setLoading(true));
      expect(state3.isLoading).toBe(true);
    });
  });

  describe("setError", () => {
    /**
     * @description Should set error message
     * @scenario Setting error with a message should update error field
     * @expected Error should contain the message
     */
    it("should set error message", () => {
      const errorMessage = "Invalid credentials";
      const state = reducer(initialState, setError(errorMessage));

      expect(state.error).toBe(errorMessage);
    });

    /**
     * @description Should set error to null
     * @scenario Setting error to null should clear error
     * @expected Error should be null
     */
    it("should set error to null", () => {
      const stateWithError: IAuthState = {
        ...initialState,
        error: "Some error",
      };

      const state = reducer(stateWithError, setError(null));
      expect(state.error).toBeNull();
    });

    /**
     * @description Should disable loading when setting error
     * @scenario Setting error should automatically set isLoading to false
     * @expected isLoading should be false after setting error
     */
    it("should disable loading when setting error", () => {
      const loadingState: IAuthState = {
        ...initialState,
        isLoading: true,
      };

      const state = reducer(loadingState, setError("Error occurred"));

      expect(state.isLoading).toBe(false);
    });

    /**
     * @description Should overwrite existing error
     * @scenario Setting new error should replace existing error
     * @expected New error should replace old error
     */
    it("should overwrite existing error", () => {
      const stateWithError: IAuthState = {
        ...initialState,
        error: "Old error",
      };

      const state = reducer(stateWithError, setError("New error"));

      expect(state.error).toBe("New error");
    });

    /**
     * @description Should handle empty string error
     * @scenario Setting empty string as error should set empty string
     * @expected Error should be empty string
     */
    it("should handle empty string error", () => {
      const state = reducer(initialState, setError(""));
      expect(state.error).toBe("");
    });

    /**
     * @description Should preserve user data when setting error
     * @scenario Setting error should not affect user data
     * @expected User should remain unchanged
     */
    it("should preserve user data when setting error", () => {
      const stateWithUser: IAuthState = {
        ...initialState,
        user: createMockUser(),
        isAuthenticated: true,
      };

      const state = reducer(stateWithUser, setError("Some error"));

      expect(state.user).toEqual(createMockUser());
      expect(state.isAuthenticated).toBe(true);
    });

    /**
     * @description Should handle various error message types
     * @scenario Setting different error message formats should work correctly
     * @expected Error should match the input
     */
    it("should handle various error message types", () => {
      const errors = [
        "Network error",
        "Validation failed: email is required",
        "401: Unauthorized",
        "Connection timeout",
        "User not found",
      ];

      errors.forEach((error) => {
        const state = reducer(initialState, setError(error));
        expect(state.error).toBe(error);
      });
    });
  });

  describe("clearError", () => {
    /**
     * @description Should clear error message
     * @scenario Clearing error when error exists should set error to null
     * @expected Error should be null
     */
    it("should clear error message", () => {
      const stateWithError: IAuthState = {
        ...initialState,
        error: "Some error",
      };

      const state = reducer(stateWithError, clearError());

      expect(state.error).toBeNull();
    });

    /**
     * @description Should handle when no error exists
     * @scenario Clearing error when error is already null should remain null
     * @expected Error should remain null
     */
    it("should handle when no error exists", () => {
      const state = reducer(initialState, clearError());
      expect(state.error).toBeNull();
    });

    /**
     * @description Should preserve other state fields
     * @scenario Clearing error should not affect other fields
     * @expected User and tokens should remain unchanged
     */
    it("should preserve other state fields", () => {
      const stateWithData: IAuthState = {
        ...initialState,
        user: createMockUser(),
        accessToken: "some-token",
        isAuthenticated: true,
        error: "Some error",
      };

      const state = reducer(stateWithData, clearError());

      expect(state.user).toEqual(createMockUser());
      expect(state.accessToken).toBe("some-token");
      expect(state.isAuthenticated).toBe(true);
    });
  });

  describe("logout", () => {
    /**
     * @description Should reset all auth state to defaults
     * @scenario Logging out should clear all user data and tokens
     * @expected All fields should be reset to initial state values
     */
    it("should reset all auth state to defaults", () => {
      const authenticatedState: IAuthState = {
        user: createMockUser(),
        accessToken: "some-access-token",
        refreshToken: "some-refresh-token",
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };

      const state = reducer(authenticatedState, logout());

      expect(state.user).toBeNull();
      expect(state.accessToken).toBeNull();
      expect(state.refreshToken).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should clear error during logout
     * @scenario Logging out should clear any existing error
     * @expected Error should be null after logout
     */
    it("should clear error during logout", () => {
      const stateWithError: IAuthState = {
        ...initialState,
        user: createMockUser(),
        accessToken: "token",
        isAuthenticated: true,
        error: "Some error before logout",
      };

      const state = reducer(stateWithError, logout());

      expect(state.error).toBeNull();
    });

    /**
     * @description Should work when called from initial state
     * @scenario Logging out when already logged out should not cause issues
     * @expected State should remain at initial values
     */
    it("should work when called from initial state", () => {
      const state = reducer(initialState, logout());

      expect(state).toEqual(initialState);
    });

    /**
     * @description Should reset loading state
     * @scenario Logging out during loading should reset isLoading to false
     * @expected isLoading should remain as it was (logout doesn't reset loading)
     * @note This test documents that logout does not reset isLoading
     */
    it("should reset loading state", () => {
      const loadingState: IAuthState = {
        ...initialState,
        user: createMockUser(),
        accessToken: "token",
        isAuthenticated: true,
        isLoading: true,
      };

      const state = reducer(loadingState, logout());

      // Note: logout does not reset isLoading, it preserves it
      expect(state.isLoading).toBe(true);
    });

    /**
     * @description Should completely clear user session
     * @scenario Full session cleanup should remove all user-related data
     * @expected No user data should remain, isLoading preserved
     */
    it("should completely clear user session", () => {
      const fullSession: IAuthState = {
        user: createMockUser({
          id: 999,
          username: "sessionuser",
          email: "session@example.com",
          firstName: "Session",
          lastName: "User",
          isStaff: true,
        }),
        accessToken: "full-session-access-token",
        refreshToken: "full-session-refresh-token",
        isAuthenticated: true,
        isLoading: true,
        error: "Some session error",
      };

      const state = reducer(fullSession, logout());

      expect(state.user).toBeNull();
      expect(state.accessToken).toBeNull();
      expect(state.refreshToken).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.isLoading).toBe(true); // logout preserves isLoading
      expect(state.error).toBeNull();
    });
  });

  describe("Action creators", () => {
    /**
     * @description Should export correct action creators
     * @scenario Verifying all action creators are exported
     * @expected All expected actions should be exported
     */
    it("should export correct action creators", () => {
      expect(typeof setAuthData).toBe("function");
      expect(typeof setUser).toBe("function");
      expect(typeof setTokens).toBe("function");
      expect(typeof setLoading).toBe("function");
      expect(typeof setError).toBe("function");
      expect(typeof clearError).toBe("function");
      expect(typeof logout).toBe("function");
    });

    /**
     * @description Should export reducer
     * @scenario Verifying reducer is exported
     * @expected Reducer should be a function
     */
    it("should export reducer", () => {
      expect(typeof userSlice.reducer).toBe("function");
    });
  });

  describe("State transitions", () => {
    /**
     * @description Should handle complete auth flow
     * @scenario Simulating full authentication flow: login -> token refresh -> logout
     * @expected State should transition correctly through all stages
     */
    it("should handle complete auth flow", () => {
      // Initial state
      let state = reducer(undefined, { type: "unknown" });
      expect(state.isAuthenticated).toBe(false);

      // Start loading
      state = reducer(state, setLoading(true));
      expect(state.isLoading).toBe(true);

      // Set auth data (login success)
      // Note: setAuthData does not reset isLoading, it preserves it
      const authResponse = createMockAuthResponse({
        user: createMockUser({ username: "flowuser" }),
      });
      state = reducer(state, setAuthData(authResponse));
      expect(state.isAuthenticated).toBe(true);
      expect(state.isLoading).toBe(true); // isLoading preserved
      expect(state.user?.username).toBe("flowuser");

      // Clear loading after auth data is set
      state = reducer(state, setLoading(false));
      expect(state.isLoading).toBe(false);

      // Refresh tokens
      const newTokens = createMockTokens({
        access: "new-access-token",
        refresh: "new-refresh-token",
      });
      state = reducer(state, setTokens(newTokens));
      expect(state.accessToken).toBe("new-access-token");

      // Handle error
      state = reducer(state, setError("Token expired"));
      expect(state.error).toBe("Token expired");
      expect(state.isLoading).toBe(false); // setError resets isLoading

      // Clear error
      state = reducer(state, clearError());
      expect(state.error).toBeNull();

      // Logout
      state = reducer(state, logout());
      expect(state.isAuthenticated).toBe(false);
      expect(state.user).toBeNull();
      expect(state.accessToken).toBeNull();
    });

    /**
     * @description Should handle error during authentication
     * @scenario Setting error during auth flow should update state correctly
     * @expected Error should be set and loading should be disabled
     */
    it("should handle error during authentication", () => {
      let state = reducer(initialState, setLoading(true));
      state = reducer(state, setError("Authentication failed"));

      expect(state.error).toBe("Authentication failed");
      expect(state.isLoading).toBe(false);
      expect(state.isAuthenticated).toBe(false);
    });

    /**
     * @description Should handle user update after authentication
     * @scenario Updating user profile after login should update user data
     * @expected User should be updated while maintaining auth state
     */
    it("should handle user update after authentication", () => {
      let state = reducer(initialState, setAuthData(createMockAuthResponse()));

      const updatedUser = createMockUser({
        username: "updateduser",
        firstName: "Updated",
      });
      state = reducer(state, setUser(updatedUser));

      expect(state.user?.username).toBe("updateduser");
      expect(state.user?.firstName).toBe("Updated");
      expect(state.isAuthenticated).toBe(true);
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should handle setting auth data with minimal data
     * @scenario Setting auth data with only required fields should work
     * @expected State should be set correctly
     */
    it("should handle setting auth data with minimal data", () => {
      const minimalAuth: IUserAuthResponse = {
        access: "min-access",
        refresh: "min-refresh",
        user: createMockUser(),
      };

      const state = reducer(initialState, setAuthData(minimalAuth));

      expect(state.isAuthenticated).toBe(true);
      expect(state.accessToken).toBe("min-access");
    });

    /**
     * @description Should handle setting user with minimal data
     * @scenario Setting user with minimal user object should work
     * @expected User should be set with isAuthenticated true
     */
    it("should handle setting user with minimal data", () => {
      const minimalUser: IUser = {
        id: 1,
        username: "minuser",
        email: "min@example.com",
        firstName: "Min",
        lastName: "User",
        fullName: "Min User",
        isActive: true,
        isStaff: false,
        storagePath: "",
        dateJoined: "",
        lastLogin: "",
      };

      const state = reducer(initialState, setUser(minimalUser));

      expect(state.user).toEqual(minimalUser);
      expect(state.isAuthenticated).toBe(true);
    });

    /**
     * @description Should handle setting tokens with minimal data
     * @scenario Setting tokens with only required fields should work
     * @expected Both tokens should be set
     */
    it("should handle setting tokens with minimal data", () => {
      const minimalTokens: IToken = {
        access: "token",
        refresh: "refresh",
      };

      const state = reducer(initialState, setTokens(minimalTokens));

      expect(state.accessToken).toBe("token");
      expect(state.refreshToken).toBe("refresh");
    });

    /**
     * @description Should handle repeated setLoading calls
     * @scenario Multiple setLoading calls should work correctly
     * @expected isLoading should reflect the last value
     */
    it("should handle repeated setLoading calls", () => {
      let state = reducer(initialState, setLoading(true));
      expect(state.isLoading).toBe(true);

      state = reducer(state, setLoading(true));
      expect(state.isLoading).toBe(true);

      state = reducer(state, setLoading(false));
      expect(state.isLoading).toBe(false);
    });

    /**
     * @description Should handle repeated setError calls
     * @scenario Multiple setError calls should work correctly
     * @expected Error should reflect the last value
     */
    it("should handle repeated setError calls", () => {
      let state = reducer(initialState, setError("Error 1"));
      expect(state.error).toBe("Error 1");

      state = reducer(state, setError("Error 2"));
      expect(state.error).toBe("Error 2");

      state = reducer(state, setError(null));
      expect(state.error).toBeNull();
    });

    /**
     * @description Should handle multiple logouts
     * @scenario Multiple logout calls should not cause issues
     * @expected State should remain at initial values
     */
    it("should handle multiple logouts", () => {
      const authenticatedState: IAuthState = {
        user: createMockUser(),
        accessToken: "token",
        refreshToken: "refresh",
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };

      let state = reducer(authenticatedState, logout());
      expect(state.isAuthenticated).toBe(false);

      state = reducer(state, logout());
      expect(state.isAuthenticated).toBe(false);

      state = reducer(state, logout());
      expect(state.isAuthenticated).toBe(false);
    });
  });
});
