import { describe, expect, it } from "vitest";

import { validatePasswordConfirm } from "./validatePasswordConfirm";

/** Centralized error messages for easy maintenance */
const ERRORS = {
  REQUIRED: "Подтверждение пароля обязательно",
  NOT_MATCH: "Пароли не совпадают",
} as const;

/** Helper to create expected invalid result */
const invalid = (error: (typeof ERRORS)[keyof typeof ERRORS]) => ({
  isValid: false,
  error,
});

/** Helper to create expected valid result */
const valid = () => ({ isValid: true });

describe("validatePasswordConfirm", () => {
  describe("Empty or falsy confirmation password", () => {
    /**
     * @description Should return invalid for empty string confirmation
     * @scenario Empty string for password confirmation should trigger validation error
     * @expected Error message: "Подтверждение пароля обязательно"
     */
    it("should return invalid for empty string", () => {
      expect(validatePasswordConfirm("", "password123")).toEqual(
        invalid(ERRORS.REQUIRED),
      );
    });

    /**
     * @description Should return invalid for whitespace-only string
     * @scenario Whitespace-only string has length > 0, so comparison fails
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for whitespace-only string", () => {
      expect(validatePasswordConfirm("   ", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for tab-only string
     * @scenario Tab-only string has length > 0, so comparison fails
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for tab-only string", () => {
      const tab = "\t";
      expect(validatePasswordConfirm(tab, "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for newline-only string
     * @scenario Newline-only string has length > 0, so comparison fails
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for newline-only string", () => {
      const newline = "\n";
      expect(validatePasswordConfirm(newline, "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for undefined value
     * @scenario Undefined value should trigger validation error
     * @expected Error message: "Подтверждение пароля обязательно"
     */
    it("should return invalid for undefined", () => {
      expect(
        validatePasswordConfirm(undefined as unknown as string, "password123"),
      ).toEqual(invalid(ERRORS.REQUIRED));
    });

    /**
     * @description Should return invalid for null value
     * @scenario Null value should trigger validation error
     * @expected Error message: "Подтверждение пароля обязательно"
     */
    it("should return invalid for null", () => {
      expect(
        validatePasswordConfirm(null as unknown as string, "password123"),
      ).toEqual(invalid(ERRORS.REQUIRED));
    });
  });

  describe("Confirmation password does not match original password", () => {
    /**
     * @description Should return invalid for completely different passwords
     * @scenario Confirmation password completely different from original should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for completely different passwords", () => {
      expect(validatePasswordConfirm("different", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for case-sensitive mismatch
     * @scenario Confirmation with different case should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for case-sensitive mismatch", () => {
      expect(validatePasswordConfirm("PASSWORD123", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for missing character at end
     * @scenario Confirmation missing last character should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for missing character at end", () => {
      expect(validatePasswordConfirm("password12", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for extra character at end
     * @scenario Confirmation with extra character at end should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for extra character at end", () => {
      expect(validatePasswordConfirm("password1234", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for whitespace difference
     * @scenario Confirmation with leading whitespace should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for leading whitespace", () => {
      expect(validatePasswordConfirm(" password123", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for trailing whitespace
     * @scenario Confirmation with trailing whitespace should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for trailing whitespace", () => {
      expect(validatePasswordConfirm("password123 ", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for number substitution
     * @scenario Confirmation with number substituted should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for number substitution", () => {
      expect(validatePasswordConfirm("passw0rd123", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for empty original password with non-empty confirmation
     * @scenario Empty original password should still fail when confirmation is not empty
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid when original is empty but confirmation is not", () => {
      expect(validatePasswordConfirm("password123", "")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should return invalid for special character difference
     * @scenario Confirmation with different special character should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for special character difference", () => {
      expect(validatePasswordConfirm("password123@", "password123!")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });
  });

  describe("Valid confirmation password matching original", () => {
    /**
     * @description Should return valid for exact match
     * @scenario Confirmation password exactly matching original should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for exact match", () => {
      expect(validatePasswordConfirm("password123", "password123")).toEqual(
        valid(),
      );
    });

    /**
     * @description Should return valid for matching with special characters
     * @scenario Confirmation with special characters matching original should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching with special characters", () => {
      expect(validatePasswordConfirm("Pass123!", "Pass123!")).toEqual(valid());
    });

    /**
     * @description Should return valid for matching with numbers only
     * @scenario Confirmation with numbers only matching original should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching with numbers only", () => {
      expect(validatePasswordConfirm("123456", "123456")).toEqual(valid());
    });

    /**
     * @description Should return valid for matching with letters only
     * @scenario Confirmation with letters only matching original should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching with letters only", () => {
      expect(validatePasswordConfirm("password", "password")).toEqual(valid());
    });

    /**
     * @description Should return valid for matching with mixed case
     * @scenario Confirmation with mixed case matching original should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching with mixed case", () => {
      expect(validatePasswordConfirm("PaSsWoRd123", "PaSsWoRd123")).toEqual(
        valid(),
      );
    });

    /**
     * @description Should return valid for matching long password
     * @scenario Long password confirmation matching original should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching long password", () => {
      expect(
        validatePasswordConfirm(
          "VeryLongSecurePassword123!@#",
          "VeryLongSecurePassword123!@#",
        ),
      ).toEqual(valid());
    });

    /**
     * @description Should return valid for matching with spaces in password
     * @scenario Password with spaces matching confirmation should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching with spaces in password", () => {
      expect(
        validatePasswordConfirm("my password 123", "my password 123"),
      ).toEqual(valid());
    });

    /**
     * @description Should return valid for matching with unicode characters
     * @scenario Password with unicode matching confirmation should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for matching with unicode characters", () => {
      expect(validatePasswordConfirm("пароль123", "пароль123")).toEqual(
        valid(),
      );
    });

    /**
     * @description Should return invalid for empty strings (both empty)
     * @scenario Both confirmation and original empty should fail (required check)
     * @expected Error message: "Подтверждение пароля обязательно"
     */
    it("should return invalid for both strings empty", () => {
      expect(validatePasswordConfirm("", "")).toEqual(invalid(ERRORS.REQUIRED));
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should be case-sensitive validation
     * @scenario Function should perform case-sensitive comparison
     * @expected Different cases should not match
     */
    it("should perform case-sensitive validation", () => {
      expect(validatePasswordConfirm("Password123", "password123")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should handle very short matching passwords
     * @scenario Short identical passwords should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for very short matching passwords", () => {
      expect(validatePasswordConfirm("ab", "ab")).toEqual(valid());
    });

    /**
     * @description Should handle whitespace-only original password
     * @scenario Whitespace-only original with same confirmation should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid when original is whitespace only", () => {
      expect(validatePasswordConfirm("   ", "   ")).toEqual(valid());
    });

    /**
     * @description Should handle single character passwords
     * @scenario Single character matching confirmation should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for single character matching passwords", () => {
      expect(validatePasswordConfirm("a", "a")).toEqual(valid());
    });

    /**
     * @description Should return invalid for single character not matching
     * @scenario Single character confirmation not matching should fail
     * @expected Error message: "Пароли не совпадают"
     */
    it("should return invalid for single character not matching", () => {
      expect(validatePasswordConfirm("a", "b")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should handle identical unicode but different ASCII
     * @scenario Different representations should be treated as different
     * @expected Error message: "Пароли не совпадают"
     */
    it("should distinguish between similar looking characters", () => {
      // Latin 'a' vs Cyrillic 'а' - these look similar but are different
      expect(validatePasswordConfirm("раrоl", "пароль")).toEqual(
        invalid(ERRORS.NOT_MATCH),
      );
    });

    /**
     * @description Should handle newline characters in password
     * @scenario Passwords with newlines matching should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for passwords with newlines matching", () => {
      const newlinePass = "pass\nword";
      expect(validatePasswordConfirm(newlinePass, newlinePass)).toEqual(
        valid(),
      );
    });

    /**
     * @description Should handle tab characters in password
     * @scenario Passwords with tabs matching should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for passwords with tabs matching", () => {
      const tabPass = "pass\tword";
      expect(validatePasswordConfirm(tabPass, tabPass)).toEqual(valid());
    });
  });
});
