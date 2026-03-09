import type { IValidationResult } from "../types/validation";

/**
 * Validates an email string according to standard email format rules.
 *
 * The email must:
 * - Not be empty or contain only whitespace.
 * - Match the general structure of a valid email address (local-part@domain).
 * - Contain only allowed characters in both local and domain parts.
 * - Have a valid top-level domain (at least two characters).
 *
 * @param value - The email string to validate.
 * @returns An object indicating whether the email is valid and an error message
 *  if invalid.
 *
 * @example
 * const result = validateEmail("user@example.com");
 * if (!result.isValid) {
 *   console.error(result.error);
 * }
 */
export const validateEmail = (value: string): IValidationResult => {
  if (!value || value.trim().length === 0) {
    return { isValid: false, error: "Email обязателен для заполнения" };
  }

  const trimmedValue = value.trim();

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(trimmedValue)) {
    return { isValid: false, error: "Введите корректный email адрес" };
  }

  return { isValid: true };
};
