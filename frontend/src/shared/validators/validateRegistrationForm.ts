import type { IValidationResult } from "../types/validation";
import { validateEmail } from "./validateEmail";
import { validateLogin } from "./validateLogin";
import { validateName } from "./validateName";
import { validatePassword } from "./validatePassword";
import { validatePasswordConfirm } from "./validatePasswordConfirm";

/**
 * Data structure for registration form fields.
 */
interface RegistrationFieldsData {
  username: string;
  email: string;
  password: string;
  passwordConfirm: string;
  firstName: string;
  lastName: string;
}

/**
 * Validates all fields of a registration form.
 *
 * Applies specific validation rules to each field using dedicated validation
 *  functions:
 * - `username`: validated by {@link validateLogin}
 * - `email`: validated by {@link validateEmail}
 * - `password`: validated by {@link validatePassword}
 * - `passwordConfirm`: validated by {@link validatePasswordConfirm}
 *  (compares with password)
 * - `firstName` and `lastName`: validated by {@link validateName} with
 *  appropriate labels
 *
 * @param data - An object containing the registration form fields to validate.
 * @returns An object mapping each field name to its validation result
 *  (`isValid` and optional `error`).
 *
 * @example
 * const formData = { username: "user123", email: "user@example.com", ... };
 * const results = validateRegistrationForm(formData);
 * Object.keys(results).forEach(field => {
 *   if (!results[field].isValid) {
 *     console.error(`${field}: ${results[field].error}`);
 *   }
 * });
 */
export const validateRegistrationForm = (
  data: RegistrationFieldsData,
): Record<string, IValidationResult> => {
  return {
    username: validateLogin(data.username),
    email: validateEmail(data.email),
    password: validatePassword(data.password),
    passwordConfirm: validatePasswordConfirm(
      data.passwordConfirm,
      data.password,
    ),
    firstName: validateName(data.firstName, "Имя"),
    lastName: validateName(data.lastName, "Фамилия"),
  };
};
