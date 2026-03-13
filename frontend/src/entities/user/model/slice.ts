import { createSlice, type PayloadAction } from "@reduxjs/toolkit";
import type { IAuthState, IToken, IUser, IUserAuthResponse } from "./types";

/**
 * The initial state for the authentication slice of the Redux store.
 *
 * Defines the default values for user authentication data and related status
 * flags.
 */
const initialState: IAuthState = {
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
};

/**
 * Redux slice for managing authentication state.
 */
export const userSlice = createSlice({
  name: "user",
  initialState,
  reducers: {
    /**
     * Sets the authentication data after successful login or registration.
     *
     * @param state - The current state.
     * @param action - Action containing the payload with access token, refresh
     *  token, and user data.
     */
    setAuthData: (state, action: PayloadAction<IUserAuthResponse>) => {
      const { access, refresh, user } = action.payload;

      state.accessToken = access;
      state.refreshToken = refresh;
      state.user = user;
      state.isAuthenticated = true;
      state.error = null;
    },

    /**
     * Updates the user object in the state.
     *
     * Also sets `isAuthenticated` to `true` if user is not null, otherwise
     * `false`.
     *
     * @param state - The current state.
     * @param action - Action containing the user object or null.
     */
    setUser: (state, action: PayloadAction<IUser | null>) => {
      state.user = action.payload;
      state.isAuthenticated = !!action.payload;
    },

    /**
     * Updates only the authentication tokens without affecting other fields.
     *
     * Useful when refreshing tokens.
     *
     * @param state - The current state.
     * @param action - Action containing the new access and refresh tokens.
     */
    setTokens: (state, action: PayloadAction<IToken>) => {
      state.accessToken = action.payload.access;
      state.refreshToken = action.payload.refresh;
    },

    /**
     * Sets the loading state during authentication requests.
     *
     * @param state - The current state.
     * @param action - Boolean flag indicating whether loading is active.
     */
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.isLoading = action.payload;
    },

    /**
     * Sets an error message and disables loading.
     *
     * @param state - The current state.
     * @param action - Error message string or null.
     */
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload;
      state.isLoading = false;
    },

    /**
     * Clears any existing error message without changing other state values.
     *
     * @param state - The current state.
     */
    clearError: (state) => {
      state.error = null;
    },

    /**
     * Resets the entire authentication state to unauthenticated defaults.
     *
     * Removes user data, tokens, and authentication flags.
     *
     * @param state - The current state.
     */
    logout: (state) => {
      state.user = null;
      state.accessToken = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      state.error = null;
    },
  },
});

export const {
  setAuthData,
  setUser,
  setTokens,
  setLoading,
  setError,
  clearError,
  logout,
} = userSlice.actions;

export default userSlice.reducer;
