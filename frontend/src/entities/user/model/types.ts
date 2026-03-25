/**
 * Represents the user entity returned by the API.
 */
export interface IUser {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  fullName: string;
  isActive: boolean;
  isStaff: boolean;
  storagePath: string;
  dateJoined: string;
  lastLogin?: string | null;
}

/**
 * Payload structure for login requests.
 */
export interface IUserLogin {
  username: string;
  password: string;
}

/**
 * Payload structure for user registration requests.
 */
export interface IUserRegister {
  username: string;
  email: string;
  password: string;
  passwordConfirm: string;
  firstName: string;
  lastName: string;
}

/**
 * Structure representing authentication tokens.
 */
export interface IToken {
  access: string;
  refresh: string;
}

/**
 * Response structure returned after successful authentication
 * (login or register).
 */
export interface IUserAuthResponse extends IToken {
  user: IUser;
}

/**
 * State shape for the authentication slice in the Redux store.
 */
export interface IAuthState {
  user: IUser | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

/**
 * Type alias for the authentication state.
 */
export type UserState = IAuthState;

/**
 * User storage stats.
 */
export interface IStorageStats {
  fileCount: number;
  totalSize: number;
  totalSizeFormatted: string;
}

// =============================================================================
// TYPES FOR ADMIN API
// =============================================================================

/**
 * Response structure for user list requests.
 */
export interface IUserListResponse {
  id: number;
  username: string;
  email: string;
  isStaff: boolean;
  isActive: boolean;
}

/**
 * Response structure for user details requests.
 */
export type UserDetailsResponse = IUser;

/**
 * Response structure for storage stats requests.
 */
export interface IStorageStatsResponse {
  user: {
    id: number;
    username: string;
    email: string;
  };
  storage: {
    path: string;
    fileCount: number;
    totalSize: number;
    totalSizeFormatted: string;
  };
}

/**
 * Response structure for admin api responses.
 */
export interface IAdminApiResponse {
  detail: string;
}
