import type { IValidationResult } from "../types/validation";
import { validateLogin } from "./validateLogin";
import { validatePassword } from "./validatePassword";

/**
 * Validates the fields of a login form.
 *
 * Applies validation rules to the username and password fields using dedicated
 *  validators:
 * - `username`: validated by {@link validateLogin}
 * - `password`: validated by {@link validatePassword}
 *
 * @param data - An object containing the login form fields to validate.
 * @returns An object mapping each field name to its validation result
 *  (`isValid` and optional `error`).
 *
 * @example
 * const loginData = { username: "user123", password: "Pass123!" };
 * const results = validateLoginForm(loginData);
 * Object.keys(results).forEach(field => {
 *   if (!results[field].isValid) {
 *     console.error(`${field}: ${results[field].error}`);
 *   }
 * });
 */
export const validateLoginForm = (data: {
  username: string;
  password: string;
}): Record<string, IValidationResult> => {
  return {
    username: validateLogin(data.username),
    password: validatePassword(data.password),
  };
};
