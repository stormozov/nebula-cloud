import type { IValidationResult } from "@/shared/types/validation";

import type {
  IRegisterFormErrors,
  IRegisterFormTouched,
  IRegisterFormValues,
} from "./types";

/**
 * Creates initial touched state for all form fields.
 *
 * All fields start as untouched (false).
 */
export const createInitialTouchedState = (): IRegisterFormTouched => ({
  username: false,
  email: false,
  password: false,
  passwordConfirm: false,
  firstName: false,
  lastName: false,
});

/**
 * Creates initial form values with empty strings.
 */
export const createInitialFormValues = (): IRegisterFormValues => ({
  username: "",
  email: "",
  password: "",
  passwordConfirm: "",
  firstName: "",
  lastName: "",
});

/**
 * Maps validation results to form errors object.
 *
 * Only sets error if field was touched and validation failed.
 *
 * @param validationResults - Results from validateRegistrationForm
 * @param touched - Current touched state
 *
 * @returns Form errors object
 */
export const mapValidationResultsToErrors = (
  validationResults: Record<string, IValidationResult>,
  touched: IRegisterFormTouched,
): IRegisterFormErrors => {
  const errors: IRegisterFormErrors = {};

  (Object.keys(touched) as Array<keyof IRegisterFormTouched>).forEach(
    (field) => {
      if (touched[field] && validationResults[field]?.error) {
        errors[field] = validationResults[field].error;
      }
    },
  );

  return errors;
};

/**
 * Checks if form has any errors.
 *
 * @param errors - Form errors object
 * @returns Boolean indicating if form has errors
 */
export const hasErrors = (errors: IRegisterFormErrors): boolean => {
  return Object.values(errors).some((error) => error !== undefined);
};
