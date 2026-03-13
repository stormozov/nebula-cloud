import type { IValidationResult } from "../types/validation";

/**
 * Validates a login string according to specific rules.
 *
 * The login must:
 * - Not be empty or contain only whitespace.
 * - Have a length between 4 and 20 characters (inclusive).
 * - Start with a Latin letter (a-z, A-Z).
 * - Contain only Latin letters and digits.
 *
 * @param value - The login string to validate.
 * @returns An object indicating whether the login is valid and an error message
 *  if invalid.
 *
 * @example
 * const result = validateLogin("user123");
 * if (!result.isValid) {
 *   console.error(result.error);
 * }
 */
export const validateLogin = (value: string): IValidationResult => {
  if (!value || value.trim().length === 0) {
    return { isValid: false, error: "Логин обязателен для заполнения" };
  }

  const trimmedValue = value.trim();

  if (trimmedValue.length < 4 || trimmedValue.length > 20) {
    return {
      isValid: false,
      error: "Длина логина должна быть от 4 до 20 символов",
    };
  }

  const firstCharRegex = /^[a-zA-Z]/;
  if (!firstCharRegex.test(trimmedValue)) {
    return { isValid: false, error: "Первый символ логина должен быть буквой" };
  }

  const fullRegex = /^[a-zA-Z][a-zA-Z0-9]*$/;
  if (!fullRegex.test(trimmedValue)) {
    return {
      isValid: false,
      error: "Логин должен содержать только латинские буквы и цифры",
    };
  }

  return { isValid: true };
};
