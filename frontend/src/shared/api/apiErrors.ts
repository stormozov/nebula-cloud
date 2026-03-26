import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";

import type { IParsedApiErrors } from "@/shared/types/api-errors";

/**
 * Parses Django REST Framework validation errors.
 * Handles both field-specific errors and generic detail errors.
 *
 * @param errorData - Error response from API (400 Bad Request)
 * @param fieldMap - Optional mapping from backend field names to frontend field
 *  names
 *
 * @returns Object with fieldErrors and submitError
 *
 * @example
 * // Registration error
 * const errorData = {
 *   username: ["Пользователь с таким логином уже существует."],
 *   email: ["Пользователь с таким email уже существует."]
 * };
 * const { fieldErrors, submitError } = parseDjangoApiErrors(errorData);
 * // Returns: { fieldErrors: { username: "...", email: "..." }, submitError: undefined }
 *
 * @example
 * // Login error
 * const errorData = { detail: "Неверный логин или пароль." };
 * const { fieldErrors, submitError } = parseDjangoApiErrors(errorData);
 * // Returns: { fieldErrors: {}, submitError: "Неверный логин или пароль." }
 */
export const parseDjangoApiErrors = (
  errorData: unknown,
  fieldMap?: Record<string, string>,
): IParsedApiErrors => {
  const result: IParsedApiErrors = {
    fieldErrors: {},
    submitError: undefined,
  };

  if (!errorData || typeof errorData !== "object") {
    return result;
  }

  const data = errorData as Record<string, unknown>;
  const defaultFieldMap: Record<string, string> = {
    username: "username",
    email: "email",
    password: "password",
    password_confirm: "passwordConfirm",
    first_name: "firstName",
    last_name: "lastName",
    non_field_errors: "submit",
  };

  let map: Record<string, string>;
  if (fieldMap === undefined) {
    map = defaultFieldMap;
  } else if (Object.keys(fieldMap).length === 0) {
    map = {};
  } else {
    map = { ...defaultFieldMap, ...fieldMap };
  }

  // Handle generic "detail" error (e.g., login errors)
  if ("detail" in data && data.detail !== undefined && data.detail !== "") {
    if (typeof data.detail === "string") {
      result.submitError = data.detail;
    } else if (Array.isArray(data.detail) && data.detail.length > 0) {
      result.submitError = data.detail[0];
    }
    if (result.submitError) {
      return result;
    }
  }

  // Handle field-specific errors (e.g., registration errors)
  Object.entries(data).forEach(([field, messages]) => {
    if (Array.isArray(messages) && messages.length > 0) {
      const formField = map[field];
      if (formField) {
        result.fieldErrors[formField] = messages[0] as string;
      }
    } else if (typeof messages === "string") {
      const formField = map[field];
      if (formField) {
        result.fieldErrors[formField] = messages;
      }
    }
  });

  return result;
};

/**
 * Checks if parsed errors object has any field errors.
 * Works with Record<string, string> or undefined values.
 *
 * @param errors - Object with field names as keys and error messages as values
 * @returns true if any field has an error message
 */
export const hasFieldErrors = (
  errors: Record<string, string | undefined>,
): boolean => {
  return Object.values(errors).some(
    (error) => error !== undefined && error !== "",
  );
};

/**
 * Checks if parsed errors object has any errors (field or submit).
 *
 * @param parsedErrors - Parsed API errors object
 * @returns true if any error exists
 */
export const hasAnyErrors = (parsedErrors: IParsedApiErrors): boolean => {
  return hasFieldErrors(parsedErrors.fieldErrors) || !!parsedErrors.submitError;
};

/**
 * Checks if error is 401 (unauthorized).
 */
export const isError401 = (err: FetchBaseQueryError): boolean => {
  return (
    err && typeof err === "object" && "status" in err && err.status === 401
  );
};
