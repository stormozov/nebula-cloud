import type { RootState } from "@/app/store/store";

import type { UserState } from "./types";

const getUserState = (state: RootState): UserState => state.user;

export const selectUser = (state: RootState) => getUserState(state).user;
export const selectAccessToken = (state: RootState) =>
  getUserState(state).accessToken;
export const selectRefreshToken = (state: RootState) =>
  getUserState(state).refreshToken;
export const selectIsAuthenticated = (state: RootState) =>
  getUserState(state).isAuthenticated;
export const selectIsLoading = (state: RootState) =>
  getUserState(state).isLoading;
export const selectAuthError = (state: RootState) => getUserState(state).error;
export const selectIsStaff = (state: RootState) =>
  getUserState(state).user?.isStaff ?? false;

export const selectAuth = (state: RootState) => ({
  user: getUserState(state).user,
  accessToken: getUserState(state).accessToken,
  isAuthenticated: getUserState(state).isAuthenticated,
  isStaff: getUserState(state).user?.isStaff ?? false,
});
