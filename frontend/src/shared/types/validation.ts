/**
 * Represents the result of a validation operation.
 */
export interface IValidationResult {
  isValid: boolean;
  error?: string;
}

/**
 * A function type that validates a string value and returns a validation result.
 */
export type ValidatorFn = (
  value: string,
  confirmValue?: string,
) => IValidationResult;
