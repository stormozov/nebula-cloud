import type { IValidationResult } from "../types/validation";

/**
 * Validates a name field (e.g., first name, last name) according to common rules.
 *
 * The name must:
 * - Not be empty or contain only whitespace.
 * - Be at least 2 characters long after trimming.
 * - Contain only letters (Latin and Cyrillic, including `ё` and `Ё`), spaces,
 *  and hyphens.
 *
 * @param value - The name string to validate.
 * @param fieldName - The display name of the field (used in error messages).
 *  Defaults to "Имя".
 *
 * @returns An object indicating whether the name is valid and an error message
 *  if invalid.
 *
 * @example
 * const result = validateName("Иван Иванов");
 * if (!result.isValid) {
 *   console.error(result.error);
 * }
 */
export const validateName = (
  value: string,
  fieldName: string = "Имя",
): IValidationResult => {
  if (!value || value.trim().length === 0) {
    return { isValid: false, error: `${fieldName} обязательно для заполнения` };
  }

  const trimmedValue = value.trim();

  if (trimmedValue.length < 2) {
    return {
      isValid: false,
      error: `${fieldName} должно содержать не менее 2 символов`,
    };
  }

  const nameRegex = /^[a-zA-Zа-яА-ЯёЁ\s-]+$/;
  if (!nameRegex.test(trimmedValue)) {
    return {
      isValid: false,
      error: `${fieldName} должно содержать только буквы`,
    };
  }

  return { isValid: true };
};
