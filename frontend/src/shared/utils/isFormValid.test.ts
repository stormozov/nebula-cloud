import { describe, expect, it } from "vitest";

import type { IValidationResult } from "@/shared/types/validation";
import { isFormValid } from "./isFormValid";

/** Helper to create expected valid result */
const valid = (): IValidationResult => ({ isValid: true });

/** Helper to create expected invalid result */
const invalid = (error: string): IValidationResult => ({
  isValid: false,
  error,
});

describe("isFormValid", () => {
  describe("All fields are valid", () => {
    /**
     * @description Should return true when all fields have isValid: true
     * @scenario All validation results in the form are valid
     * @expected Returns true
     */
    it("should return true when all fields are valid", () => {
      const validationResults = {
        username: valid(),
        email: valid(),
        password: valid(),
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should return true for single valid field
     * @scenario Form has only one field that is valid
     * @expected Returns true
     */
    it("should return true for single valid field", () => {
      const validationResults = {
        username: valid(),
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should return true for empty form
     * @scenario Form has no fields (empty object)
     * @expected Returns true (vacuous truth)
     */
    it("should return true for empty form", () => {
      const validationResults = {};
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should return true when all fields have no error message
     * @scenario All valid fields may or may not have error property
     * @expected Returns true
     */
    it("should return true for valid fields with undefined error", () => {
      const validationResults = {
        field1: { isValid: true },
        field2: { isValid: true, error: undefined },
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should return true for multiple valid fields
     * @scenario Form has many fields, all valid
     * @expected Returns true
     */
    it("should return true for multiple valid fields", () => {
      const validationResults = {
        field1: valid(),
        field2: valid(),
        field3: valid(),
        field4: valid(),
        field5: valid(),
      };
      expect(isFormValid(validationResults)).toBe(true);
    });
  });

  describe("One or more fields are invalid", () => {
    /**
     * @description Should return false when single field is invalid
     * @scenario One field in the form has isValid: false
     * @expected Returns false
     */
    it("should return false when single field is invalid", () => {
      const validationResults = {
        username: valid(),
        email: invalid("Invalid email format"),
        password: valid(),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should return false when first field is invalid
     * @scenario First field in the form is invalid
     * @expected Returns false
     */
    it("should return false when first field is invalid", () => {
      const validationResults = {
        username: invalid("Username is required"),
        email: valid(),
        password: valid(),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should return false when last field is invalid
     * @scenario Last field in the form is invalid
     * @expected Returns false
     */
    it("should return false when last field is invalid", () => {
      const validationResults = {
        username: valid(),
        email: valid(),
        password: invalid("Password is too weak"),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should return false when all fields are invalid
     * @scenario All fields in the form have isValid: false
     * @expected Returns false
     */
    it("should return false when all fields are invalid", () => {
      const validationResults = {
        username: invalid("Username is required"),
        email: invalid("Invalid email format"),
        password: invalid("Password is too weak"),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should return false when multiple fields are invalid
     * @scenario More than one field is invalid
     * @expected Returns false
     */
    it("should return false when multiple fields are invalid", () => {
      const validationResults = {
        username: valid(),
        email: invalid("Invalid email"),
        password: invalid("Weak password"),
        confirmPassword: invalid("Passwords do not match"),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should return false for single invalid field
     * @scenario Form has only one field and it is invalid
     * @expected Returns false
     */
    it("should return false for single invalid field", () => {
      const validationResults = {
        username: invalid("Username is required"),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should handle fields with empty error string
     * @scenario Field has isValid: true but error is empty string
     * @expected Returns true
     */
    it("should return true for valid field with empty error string", () => {
      const validationResults = {
        username: { isValid: true, error: "" },
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should handle mixed valid and invalid with error messages
     * @scenario Some fields have detailed error messages
     * @expected Returns false due to invalid fields
     */
    it("should return false when fields have detailed error messages", () => {
      const validationResults = {
        username: valid(),
        email: invalid(
          "Please enter a valid email address like user@example.com",
        ),
        password: invalid(
          "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, and one number",
        ),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle fields with numeric error codes
     * @scenario Error property contains numeric value as string
     * @expected Returns based on isValid value
     */
    it("should handle fields with numeric error codes", () => {
      const validationResults = {
        field1: valid(),
        field2: invalid("400"),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle unicode characters in field names
     * @scenario Field names contain unicode characters
     * @expected Returns true when all fields are valid
     */
    it("should handle unicode characters in field names", () => {
      const validationResults = {
        имя_пользователя: valid(),
        электронная_почта: valid(),
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should handle special characters in field names
     * @scenario Field names contain special characters
     * @expected Returns false when one field is invalid
     */
    it("should handle special characters in field names", () => {
      const validationResults = {
        "field-name": valid(),
        field_name: valid(),
        "field.name": invalid("Invalid value"),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle single character field names
     * @scenario Field names are single characters
     * @expected Returns based on isValid values
     */
    it("should handle single character field names", () => {
      const validationResults = {
        a: valid(),
        b: invalid("Error"),
        c: valid(),
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle very long field names
     * @scenario Field names are very long strings
     * @expected Returns true when all fields are valid
     */
    it("should handle very long field names", () => {
      const longFieldName = "a".repeat(1000);
      const validationResults = {
        [longFieldName]: valid(),
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should handle undefined error property
     * @scenario Field has isValid: false but error is undefined
     * @expected Returns false
     */
    it("should return false when error is undefined", () => {
      const validationResults = {
        field: { isValid: false, error: undefined },
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle null error property
     * @scenario Field has isValid: false but error is null
     * @expected Returns false
     */
    it("should return false when error is null", () => {
      const validationResults = {
        field: { isValid: false, error: undefined as unknown as string },
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle numeric isValid value (truthy)
     * @scenario Field has isValid: 1 (truthy number)
     * @expected Returns true
     */
    it("should return true for truthy numeric isValid", () => {
      const validationResults = {
        field: { isValid: 1 as unknown as boolean },
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should handle numeric isValid value (falsy)
     * @scenario Field has isValid: 0 (falsy number)
     * @expected Returns false
     */
    it("should return false for falsy numeric isValid", () => {
      const validationResults = {
        field: { isValid: 0 as unknown as boolean },
      };
      expect(isFormValid(validationResults)).toBe(false);
    });

    /**
     * @description Should handle string isValid value (truthy)
     * @scenario Field has isValid: "true" (truthy string)
     * @expected Returns true
     */
    it("should return true for truthy string isValid", () => {
      const validationResults = {
        field: { isValid: "true" as unknown as boolean },
      };
      expect(isFormValid(validationResults)).toBe(true);
    });

    /**
     * @description Should handle empty string isValid value
     * @scenario Field has isValid: "" (empty string)
     * @expected Returns false
     */
    it("should return false for empty string isValid", () => {
      const validationResults = {
        field: { isValid: "" as unknown as boolean },
      };
      expect(isFormValid(validationResults)).toBe(false);
    });
  });
});
