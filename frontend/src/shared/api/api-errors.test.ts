import { describe, expect, it } from "vitest";

import {
  hasAnyErrors,
  hasFieldErrors,
  parseDjangoApiErrors,
} from "./api-errors";

/** Helper to create expected result with field errors */
const fieldErrors = (errors: Record<string, string>) => ({
  fieldErrors: errors,
  submitError: undefined,
});

/** Helper to create expected result with submit error */
const submitError = (error: string) => ({
  fieldErrors: {},
  submitError: error,
});

/** Helper to create expected empty result */
const noErrors = () => ({
  fieldErrors: {},
  submitError: undefined,
});

describe("parseDjangoApiErrors", () => {
  describe("Invalid input handling", () => {
    /**
     * @description Should return empty errors for null input
     * @scenario Pass null as errorData parameter
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for null", () => {
      expect(parseDjangoApiErrors(null)).toEqual(noErrors());
    });

    /**
     * @description Should return empty errors for undefined input
     * @scenario Pass undefined as errorData parameter
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for undefined", () => {
      expect(parseDjangoApiErrors(undefined)).toEqual(noErrors());
    });

    /**
     * @description Should return empty errors for string input
     * @scenario Pass a string instead of object
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for string input", () => {
      expect(parseDjangoApiErrors("some error")).toEqual(noErrors());
    });

    /**
     * @description Should return empty errors for number input
     * @scenario Pass a number instead of object
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for number input", () => {
      expect(parseDjangoApiErrors(400)).toEqual(noErrors());
    });

    /**
     * @description Should return empty errors for array input
     * @scenario Pass an array instead of object
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for array input", () => {
      expect(parseDjangoApiErrors(["error1", "error2"])).toEqual(noErrors());
    });

    /**
     * @description Should return empty errors for boolean input
     * @scenario Pass a boolean instead of object
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for boolean input", () => {
      expect(parseDjangoApiErrors(true)).toEqual(noErrors());
    });
  });

  describe("Empty object input", () => {
    /**
     * @description Should return empty errors for empty object
     * @scenario Pass empty object as errorData
     * @expected Returns empty fieldErrors and undefined submitError
     */
    it("should return empty errors for empty object", () => {
      expect(parseDjangoApiErrors({})).toEqual(noErrors());
    });
  });

  describe("Generic detail error (login errors)", () => {
    /**
     * @description Should parse string detail error
     * @scenario API returns simple string detail for authentication failure
     * @expected Returns submitError with the detail message
     */
    it("should parse string detail error", () => {
      const errorData = { detail: "Неверный логин или пароль." };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        submitError("Неверный логин или пароль."),
      );
    });

    /**
     * @description Should return only submit error when detail is present
     * @scenario Detail field should take precedence over field errors
     * @expected Returns only submitError, fieldErrors should be empty
     */
    it("should ignore field errors when detail is present", () => {
      const errorData = {
        detail: "Authentication failed",
        username: ["Invalid username"],
        email: ["Invalid email"],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        submitError("Authentication failed"),
      );
    });

    /**
     * @description Should handle detail with empty string
     * @scenario Detail key exists but value is empty string
     * @expected Returns empty errors (empty string not treated as error)
     */
    it("should return empty errors for empty string detail", () => {
      const errorData = { detail: "" };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });

    /**
     * @description Should handle non-string detail values
     * @scenario Detail exists but is not a string (e.g., array)
     * @expected Should not treat it as submit error, returns empty errors
     */
    it("should ignore non-string detail values", () => {
      const errorData = { detail: ["Error array"] };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });
  });

  describe("Field-specific errors (registration errors)", () => {
    /**
     * @description Should parse single field error
     * @scenario API returns error for single field
     * @expected Maps backend field name to frontend field name
     */
    it("should parse single field error", () => {
      const errorData = {
        username: ["Пользователь с таким логином уже существует."],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({
          username: "Пользователь с таким логином уже существует.",
        }),
      );
    });

    /**
     * @description Should parse multiple field errors
     * @scenario API returns errors for multiple fields
     * @expected Maps all backend fields to frontend fields
     */
    it("should parse multiple field errors", () => {
      const errorData = {
        username: ["Пользователь с таким логином уже существует."],
        email: ["Пользователь с таким email уже существует."],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({
          username: "Пользователь с таким логином уже существует.",
          email: "Пользователь с таким email уже существует.",
        }),
      );
    });

    /**
     * @description Should use first message from array
     * @scenario Field has multiple error messages in array
     * @expected Returns only the first message
     */
    it("should use first message from array", () => {
      const errorData = {
        username: ["First error", "Second error", "Third error"],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({ username: "First error" }),
      );
    });

    /**
     * @description Should handle empty array
     * @scenario Field has empty array as value
     * @expected Should not add error for empty array
     */
    it("should ignore empty array", () => {
      const errorData = {
        username: [],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });

    /**
     * @description Should handle non-array string value
     * @scenario Field has string value directly (not in array)
     * @expected Should add error with the string value
     */
    it("should handle non-array string value", () => {
      const errorData = {
        username: "Single string error message",
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({ username: "Single string error message" }),
      );
    });

    /**
     * @description Should ignore unknown fields
     * @scenario Field is not in default field map
     * @expected Should not add error for unknown field
     */
    it("should ignore unknown fields", () => {
      const errorData = {
        unknown_field: ["Some error"],
        another_unknown: ["Another error"],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });

    /**
     * @description Should handle all supported default fields
     * @scenario API returns errors for all default mapped fields
     * @expected Maps all fields correctly using default mapping
     */
    it("should handle all supported default fields", () => {
      const errorData = {
        username: ["Username error"],
        email: ["Email error"],
        password: ["Password error"],
        password_confirm: ["Password confirm error"],
        first_name: ["First name error"],
        last_name: ["Last name error"],
        non_field_errors: ["Non field error"],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({
          username: "Username error",
          email: "Email error",
          password: "Password error",
          passwordConfirm: "Password confirm error",
          firstName: "First name error",
          lastName: "Last name error",
          submit: "Non field error",
        }),
      );
    });
  });

  describe("Custom field mapping", () => {
    /**
     * @description Should use custom field map when provided
     * @scenario Pass custom fieldMap parameter
     * @expected Uses custom mapping instead of default
     */
    it("should use custom field map", () => {
      const errorData = {
        user_name: ["Error"],
        e_mail: ["Error"],
      };
      const fieldMap = {
        user_name: "login",
        e_mail: "mail",
      };
      expect(parseDjangoApiErrors(errorData, fieldMap)).toEqual(
        fieldErrors({ login: "Error", mail: "Error" }),
      );
    });

    /**
     * @description Should override default mapping with custom
     * @scenario Custom map overrides default field names
     * @expected Uses custom mapping values
     */
    it("should override default mapping", () => {
      const errorData = {
        username: ["Error"],
      };
      const fieldMap = {
        username: "loginName",
      };
      expect(parseDjangoApiErrors(errorData, fieldMap)).toEqual(
        fieldErrors({ loginName: "Error" }),
      );
    });

    /**
     * @description Should handle partial custom mapping
     * @scenario Custom map only covers some fields
     * @expected Uses custom map for specified fields, default for others
     */
    it("should handle partial custom mapping", () => {
      const errorData = {
        username: ["Username error"],
        email: ["Email error"],
      };
      const fieldMap = {
        username: "login",
      };
      expect(parseDjangoApiErrors(errorData, fieldMap)).toEqual(
        fieldErrors({ login: "Username error", email: "Email error" }),
      );
    });

    /**
     * @description Should handle empty custom field map
     * @scenario Empty fieldMap object passed
     * @expected Should not map any fields
     */
    it("should handle empty custom field map", () => {
      const errorData = {
        username: ["Error"],
        email: ["Error"],
      };
      expect(parseDjangoApiErrors(errorData, {})).toEqual(noErrors());
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should handle object with detail and field errors
     * @scenario Both detail and field errors present
     * @expected Returns only submitError, fieldErrors should be empty
     */
    it("should prioritize detail over field errors", () => {
      const errorData = {
        detail: "Global error",
        username: ["Field error"],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        submitError("Global error"),
      );
    });

    /**
     * @description Should handle nested objects in field values
     * @scenario Field value is an object instead of array/string
     * @expected Should ignore non-array, non-string values
     */
    it("should ignore nested objects in field values", () => {
      const errorData = {
        username: { nested: "value" },
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });

    /**
     * @description Should handle numeric field values
     * @scenario Field value is a number
     * @expected Should ignore numeric values
     */
    it("should ignore numeric field values", () => {
      const errorData = {
        code: 12345,
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });

    /**
     * @description Should handle boolean field values
     * @scenario Field value is a boolean
     * @expected Should ignore boolean values
     */
    it("should ignore boolean field values", () => {
      const errorData = {
        is_valid: false,
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(noErrors());
    });

    /**
     * @description Should handle empty string in field array
     * @scenario Array contains empty string
     * @expected Should add empty string as error (truthy check for array length)
     */
    it("should handle empty string in field array", () => {
      const errorData = {
        username: [""],
      };
      // Empty string in non-empty array should still be processed
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({ username: "" }),
      );
    });

    /**
     * @description Should handle unicode error messages
     * @scenario Error messages contain Cyrillic characters
     * @expected Should preserve unicode characters
     */
    it("should preserve unicode characters in error messages", () => {
      const errorData = {
        username: ["Ошибка: неверный логин"],
        email: ["Ошибка: неверный email"],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({
          username: "Ошибка: неверный логин",
          email: "Ошибка: неверный email",
        }),
      );
    });

    /**
     * @description Should handle very long error messages
     * @scenario Error message is very long string
     * @expected Should preserve full error message
     */
    it("should handle very long error messages", () => {
      const longMessage = "Error ".repeat(1000);
      const errorData = {
        username: [longMessage],
      };
      expect(parseDjangoApiErrors(errorData)).toEqual(
        fieldErrors({ username: longMessage }),
      );
    });
  });
});

describe("hasFieldErrors", () => {
  describe("No field errors scenarios", () => {
    /**
     * @description Should return false for empty object
     * @scenario Pass empty object
     * @expected Returns false
     */
    it("should return false for empty object", () => {
      expect(hasFieldErrors({})).toBe(false);
    });

    /**
     * @description Should return false for object with all empty strings
     * @scenario All values are empty strings
     * @expected Returns false
     */
    it("should return false for all empty strings", () => {
      expect(hasFieldErrors({ username: "", email: "" })).toBe(false);
    });

    /**
     * @description Should return false for object with undefined values
     * @scenario All values are undefined
     * @expected Returns false
     */
    it("should return false for undefined values", () => {
      expect(hasFieldErrors({ username: undefined, email: undefined })).toBe(
        false,
      );
    });

    /**
     * @description Should return false for mixed empty and undefined
     * @scenario Object has mix of empty strings and undefined
     * @expected Returns false
     */
    it("should return false for mixed empty and undefined", () => {
      expect(hasFieldErrors({ username: "", email: undefined })).toBe(false);
    });
  });

  describe("Has field errors scenarios", () => {
    /**
     * @description Should return true for single error
     * @scenario One field has error message
     * @expected Returns true
     */
    it("should return true for single error", () => {
      expect(hasFieldErrors({ username: "Error message" })).toBe(true);
    });

    /**
     * @description Should return true for multiple errors
     * @scenario Multiple fields have error messages
     * @expected Returns true
     */
    it("should return true for multiple errors", () => {
      expect(hasFieldErrors({ username: "Error", email: "Error" })).toBe(true);
    });

    /**
     * @description Should return true when at least one field has error
     * @scenario Mix of fields with and without errors
     * @expected Returns true
     */
    it("should return true when at least one field has error", () => {
      expect(hasFieldErrors({ username: "", email: "Error" })).toBe(true);
    });

    /**
     * @description Should return true for whitespace-only string
     * @scenario Field value is whitespace only
     * @expected Returns true (whitespace is truthy string)
     */
    it("should return true for whitespace-only string", () => {
      expect(hasFieldErrors({ username: "   " })).toBe(true);
    });

    /**
     * @description Should return true for "0" string
     * @scenario Field value is string "0"
     * @expected Returns true (non-empty string is truthy)
     */
    it("should return true for '0' string", () => {
      expect(hasFieldErrors({ code: "0" })).toBe(true);
    });

    /**
     * @description Should return true for "false" string
     * @scenario Field value is string "false"
     * @expected Returns true (non-empty string is truthy)
     */
    it("should return true for 'false' string", () => {
      expect(hasFieldErrors({ valid: "false" })).toBe(true);
    });
  });
});

describe("hasAnyErrors", () => {
  describe("No errors scenarios", () => {
    /**
     * @description Should return false for empty errors
     * @scenario Both fieldErrors and submitError are empty
     * @expected Returns false
     */
    it("should return false for empty errors", () => {
      expect(hasAnyErrors({ fieldErrors: {}, submitError: undefined })).toBe(
        false,
      );
    });

    /**
     * @description Should return false when only submitError is undefined
     * @scenario fieldErrors is empty, submitError is undefined
     * @expected Returns false
     */
    it("should return false when submitError is undefined", () => {
      expect(hasAnyErrors({ fieldErrors: {} })).toBe(false);
    });
  });

  describe("Has errors scenarios", () => {
    /**
     * @description Should return true when has field errors
     * @scenario fieldErrors object has at least one error
     * @expected Returns true
     */
    it("should return true when has field errors", () => {
      expect(
        hasAnyErrors({
          fieldErrors: { username: "Error" },
          submitError: undefined,
        }),
      ).toBe(true);
    });

    /**
     * @description Should return true when has submit error
     * @scenario submitError has a value
     * @expected Returns true
     */
    it("should return true when has submit error", () => {
      expect(
        hasAnyErrors({
          fieldErrors: {},
          submitError: "Login failed",
        }),
      ).toBe(true);
    });

    /**
     * @description Should return true when has both errors
     * @scenario Both fieldErrors and submitError have values
     * @expected Returns true
     */
    it("should return true when has both errors", () => {
      expect(
        hasAnyErrors({
          fieldErrors: { username: "Error" },
          submitError: "Login failed",
        }),
      ).toBe(true);
    });

    /**
     * @description Should return true with empty string submitError
     * @scenario submitError is empty string
     * @expected Returns false (empty string is falsy)
     */
    it("should return false for empty string submitError", () => {
      expect(hasAnyErrors({ fieldErrors: {}, submitError: "" })).toBe(false);
    });
  });
});
