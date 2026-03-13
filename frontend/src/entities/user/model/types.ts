/**
 * Represents the user entity returned by the API.
 */
export interface IUser {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  isStaff: boolean;
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
