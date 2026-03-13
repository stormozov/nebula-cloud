import { describe, expect, it } from "vitest";

import type { IValidationResult } from "@/shared/types/validation";

import type {
  IRegisterFormErrors,
  IRegisterFormTouched,
  IRegisterFormValues,
} from "./types";
import * as utils from "./utils";

/**
 * @description Tests for register form utility functions
 * @group RegisterForm Utils
 */
describe("register-by-email utils", () => {
  describe("createInitialTouchedState", () => {
    /**
     * @description Should create initial touched state with all fields false
     * @scenario Calling createInitialTouchedState should return object with all false values
     * @expected Exact object matching interface with false for each field
     */
    it("should return initial touched state with all false", () => {
      const expected: IRegisterFormTouched = {
        username: false,
        email: false,
        password: false,
        passwordConfirm: false,
        firstName: false,
        lastName: false,
      };

      expect(utils.createInitialTouchedState()).toEqual(expected);
    });
  });

  // ===========================================================================

  describe("createInitialFormValues", () => {
    /**
     * @description Should create initial form values with all empty strings
     * @scenario Calling createInitialFormValues should return object with empty strings
     * @expected Exact object matching interface with "" for each field
     */
    it("should return initial form values with all empty strings", () => {
      const expected: IRegisterFormValues = {
        username: "",
        email: "",
        password: "",
        passwordConfirm: "",
        firstName: "",
        lastName: "",
      };

      expect(utils.createInitialFormValues()).toEqual(expected);
    });
  });

  // ===========================================================================

  describe("mapValidationResultsToErrors", () => {
    const mockTouchedAllFalse: IRegisterFormTouched = {
      username: false,
      email: false,
      password: false,
      passwordConfirm: false,
      firstName: false,
      lastName: false,
    };

    const mockTouchedAllTrue: IRegisterFormTouched = {
      username: true,
      email: true,
      password: true,
      passwordConfirm: true,
      firstName: true,
      lastName: true,
    };

    const mockTouchedPartial: IRegisterFormTouched = {
      username: true,
      email: true,
      password: false,
      passwordConfirm: false,
      firstName: true,
      lastName: false,
    };

    const mockValidationNoErrors: Record<string, IValidationResult> = {
      username: { isValid: true },
      email: { isValid: true },
      password: { isValid: true },
      passwordConfirm: { isValid: true },
      firstName: { isValid: true },
      lastName: { isValid: true },
    };

    const mockValidationWithErrors: Record<string, IValidationResult> = {
      username: { isValid: false, error: "Invalid username" },
      email: { isValid: false, error: "Invalid email" },
      password: { isValid: true },
      passwordConfirm: { isValid: false, error: "Passwords mismatch" },
      firstName: { isValid: true },
      lastName: { isValid: false, error: "Invalid last name" },
    };

    /**
     * @description Should not set errors for untouched fields
     * @scenario Touched all false, validation has errors → no errors in result
     * @expected Empty errors object
     */
    it("should not set errors when fields are untouched", () => {
      const result = utils.mapValidationResultsToErrors(
        mockValidationWithErrors,
        mockTouchedAllFalse,
      );

      expect(result).toEqual({});
    });

    /**
     * @description Should not set error when touched but validation valid
     * @scenario Touched true but validation isValid:true → no error
     * @expected No error for that field
     */
    it("should not set error when touched but validation is valid", () => {
      const result = utils.mapValidationResultsToErrors(
        mockValidationNoErrors,
        mockTouchedAllTrue,
      );

      expect(result).toEqual({});
    });

    /**
     * @description Should set error when touched and validation failed
     * @scenario Touched true, validation has error → set exact error message
     * @expected Error message in errors object for that field
     */
    it("should set error when touched and validation failed", () => {
      const result = utils.mapValidationResultsToErrors(
        mockValidationWithErrors,
        mockTouchedAllTrue,
      );

      const expected: IRegisterFormErrors = {
        username: "Invalid username",
        email: "Invalid email",
        passwordConfirm: "Passwords mismatch",
        lastName: "Invalid last name",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should map errors only for touched fields (partial)
     * @scenario Mixed touched state → only touched fields with errors mapped
     * @expected Errors only for username, email, firstName if applicable
     */
    it("should map errors only for touched fields in partial touched state", () => {
      const result = utils.mapValidationResultsToErrors(
        mockValidationWithErrors,
        mockTouchedPartial,
      );

      const expected: IRegisterFormErrors = {
        username: "Invalid username",
        email: "Invalid email",
        firstName: undefined, // valid
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should handle missing validation result for field
     * @scenario Touched true but no validationResults[field] → no error
     * @expected No error set
     */
    it("should not set error if no validation result for field", () => {
      const incompleteValidation: Record<string, IValidationResult> = {
        username: { isValid: false, error: "err" },
        // missing others
      };

      const result = utils.mapValidationResultsToErrors(
        incompleteValidation,
        mockTouchedAllTrue,
      );

      expect(result.username).toBe("err");
      expect(result.email).toBeUndefined();
      expect(result.password).toBeUndefined();
    });

    /**
     * @description Should return empty errors when no touched fields have errors
     * @scenario No validation errors → empty object
     * @expected {}
     */
    it("should return empty object when no errors to map", () => {
      const result = utils.mapValidationResultsToErrors(
        mockValidationNoErrors,
        mockTouchedAllTrue,
      );

      expect(result).toEqual({});
    });
  });

  // ===========================================================================

  describe("hasErrors", () => {
    const mockNoErrors: IRegisterFormErrors = {};
    const mockWithErrors: IRegisterFormErrors = {
      username: "Invalid",
      email: undefined,
      password: "Weak",
    };
    const mockOnlyUndefined: IRegisterFormErrors = {
      username: undefined,
      email: undefined,
    };

    /**
     * @description Should return false for empty errors object
     * @scenario No errors → no errors present
     * @expected false
     */
    it("should return false when no errors", () => {
      expect(utils.hasErrors(mockNoErrors)).toBe(false);
    });

    /**
     * @description Should return true when any error exists
     * @scenario Errors object has truthy error values → errors present
     * @expected true
     */
    it("should return true when errors exist", () => {
      expect(utils.hasErrors(mockWithErrors)).toBe(true);
    });

    /**
     * @description Should return false when only undefined errors
     * @scenario All error fields undefined → no actual errors
     * @expected false
     */
    it("should return false when all errors are undefined", () => {
      expect(utils.hasErrors(mockOnlyUndefined)).toBe(false);
    });
  });
});
