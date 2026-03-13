import type { IValidationResult } from "@/shared/types/validation";

/**
 * Checks whether all validation results in a form are valid.
 *
 * Iterates over the values of the provided validation results object and
 *  returns `true` only if every field has `isValid: true`. If any field
 *  is invalid, returns `false`.
 *
 * @param validationResults - An object mapping field names to their validation
 *  results.
 * @returns `true` if all fields are valid; otherwise, `false`.
 *
 * @example
 * const results = {
 *   username: { isValid: true },
 *   password: { isValid: false, error: "Invalid password" }
 * };
 * const valid = isFormValid(results); // false
 */

export const isFormValid = (
  validationResults: Record<string, IValidationResult>,
): boolean => {
  return Object.values(validationResults).every((result) => result.isValid);
};
