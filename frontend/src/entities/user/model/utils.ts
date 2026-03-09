import type { IUserRegister } from "./types";

/**
 * Transforms form data to API request format.
 *
 * Converts camelCase to snake_case for backend compatibility.
 *
 * @param data - Form values in camelCase
 * @returns Data object in snake_case for API request
 */
export const transformDataToApi = (data: IUserRegister) => ({
  username: data.username,
  email: data.email,
  password: data.password,
  password_confirm: data.passwordConfirm,
  first_name: data.firstName,
  last_name: data.lastName,
});
