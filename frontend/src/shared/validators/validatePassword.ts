import type { IValidationResult } from "../types/validation";

/**
 * Validates a password string according to security criteria.
 *
 * The password must:
 * - Not be empty.
 * - Be at least 6 characters long.
 * - Contain at least one uppercase letter (A-Z).
 * - Contain at least one digit (0-9).
 * - Contain at least one special character (non-alphanumeric).
 * - Not contain "admin" or "password" (case insensitive).
 *
 * @param value - The password string to validate.
 * @returns An object indicating whether the password is valid and an error
 *  message if invalid.
 *
 * @example
 * const result = validatePassword("Pass123!");
 * if (!result.isValid) {
 *   console.error(result.error);
 * }
 */
export const validatePassword = (value: string): IValidationResult => {
  if (!value || value.length === 0) {
    return { isValid: false, error: "Пароль обязателен для заполнения" };
  }

  if (value.length < 6) {
    return {
      isValid: false,
      error: "Пароль должен содержать не менее 6 символов",
    };
  }

  const hasUppercase = /[A-Z]/.test(value);
  if (!hasUppercase) {
    return {
      isValid: false,
      error: "Пароль должен содержать хотя бы одну заглавную букву",
    };
  }

  const hasDigit = /[0-9]/.test(value);
  if (!hasDigit) {
    return {
      isValid: false,
      error: "Пароль должен содержать хотя бы одну цифру",
    };
  }

  const hasSpecialChar = /[^a-zA-Z0-9]/.test(value);
  if (!hasSpecialChar) {
    return {
      isValid: false,
      error: "Пароль должен содержать хотя бы один специальный символ",
    };
  }

  if (
    value.toLowerCase().includes("admin") ||
    value.toLowerCase().includes("password")
  ) {
    return {
      isValid: false,
      error: "Пароль не должен содержать 'admin' или 'password'",
    };
  }

  return { isValid: true };
};
