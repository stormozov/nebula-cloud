import type { IValidationResult } from "../types/validation";

/**
 * Validates that the confirmation password matches the original password.
 *
 * The value must:
 * - Not be empty.
 * - Be identical to the provided password string.
 *
 * @param value - The confirmation password string to validate.
 * @param password - The original password string to compare against.
 * @returns An object indicating whether the confirmation is valid and an error
 *  message if invalid.
 *
 * @example
 * const result = validatePasswordConfirm("password123", "password123");
 * if (!result.isValid) {
 *   console.error(result.error);
 * }
 */
export const validatePasswordConfirm = (
  value: string,
  password: string,
): IValidationResult => {
  if (!value || value.length === 0) {
    return { isValid: false, error: "Подтверждение пароля обязательно" };
  }

  if (value !== password) {
    return { isValid: false, error: "Пароли не совпадают" };
  }

  return { isValid: true };
};
