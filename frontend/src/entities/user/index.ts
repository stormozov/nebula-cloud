// API
export {
  useGetMeQuery,
  useLoginMutation,
  useLogoutMutation,
  useRegisterMutation,
  userApi,
} from "./api/userApi";

// Selectors
export {
  selectAccessToken,
  selectAuth,
  selectAuthError,
  selectIsAuthenticated,
  selectIsLoading,
  selectIsStaff,
  selectRefreshToken,
  selectUser,
} from "./model/selectors";

// Slice
export {
  clearError,
  default as userReducer,
  logout,
  setAuthData,
  setError,
  setLoading,
  setTokens,
  setUser,
} from "./model/slice";

// Types
export type {
  IAuthState,
  IUser,
  IUserAuthResponse,
  IUserLogin,
  IUserRegister,
  UserState,
} from "./model/types";
