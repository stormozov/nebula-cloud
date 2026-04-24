import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import axios from "axios";

import type { IParsedApiErrors } from "@/shared/types/api";

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

/**
 * Extracts a human-readable error message from an unknown `detail` value.
 *
 * @param detail - The error detail to extract a message from. Can be any type.
 * @returns A formatted error message as a string.
 *
 * @example
 * ```ts
 * extractDetailMessage("Invalid input"); // → "Invalid input"
 * extractDetailMessage(["Error 1", "Error 2"]); // → "Error 1; Error 2"
 * extractDetailMessage([{ string: "Field is required" }]); // → "Field is required"
 * ```
 */
const extractDetailMessage = (detail: unknown): string => {
  // String case
  if (typeof detail === "string") return detail;

  // Array case
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0];
    if (typeof first === "string") return detail.join("; ");
    // Массив объектов ErrorDetail
    if (typeof first === "object" && first !== null && "string" in first) {
      return detail
        .map((item) => (item as { string?: string }).string || String(item))
        .join("; ");
    }
  }

  // Object case
  if (typeof detail === "object" && detail !== null && "string" in detail) {
    return (detail as { string: string }).string;
  }

  // Fallback
  return JSON.stringify(detail);
};

/**
 * Extracts a user-friendly error message from an Axios error response.
 *
 * @param error - The unknown error object, expected to be an Axios error.
 * @returns A formatted error message as a string, or `null` if no valid error
 * structure is found.
 *
 * @example
 * ```ts
 * try {
 *   await axios.get("/api/protected");
 * } catch (error) {
 *   const message = extractApiErrorMessage(error);
 *   if (message) console.error("API Error:", message);
 * }
 * ```
 */
export const extractApiErrorMessage = (error: unknown): string | null => {
  if (!axios.isAxiosError(error) || !error.response?.data) return null;

  const data = error.response.data;

  // 1. Direct field detail
  if (data.detail) return extractDetailMessage(data.detail);

  // 2. DRF often returns errors in the fields, so we look for the first one
  for (const key of Object.keys(data)) {
    const value = data[key];
    if (Array.isArray(value) && value.length > 0) {
      return extractDetailMessage(value);
    }
    if (typeof value === "string") return value;
  }

  // 3. The fallback option is the entire object as a string
  return JSON.stringify(data);
};
