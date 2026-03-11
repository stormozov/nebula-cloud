import { describe, expect, it } from "vitest";

import { validatePassword } from "./validatePassword";

/** Centralized error messages for easy maintenance */
const ERRORS = {
  REQUIRED: "Пароль обязателен для заполнения",
  MIN_LENGTH: "Пароль должен содержать не менее 6 символов",
  UPPERCASE: "Пароль должен содержать хотя бы одну заглавную букву",
  DIGIT: "Пароль должен содержать хотя бы одну цифру",
  SPECIAL: "Пароль должен содержать хотя бы один специальный символ",
  FORBIDDEN: "Пароль не должен содержать 'admin' или 'password'",
} as const;

/** Helper to create expected invalid result */
const invalid = (error: (typeof ERRORS)[keyof typeof ERRORS]) => ({
  isValid: false,
  error,
});

/** Helper to create expected valid result */
const valid = () => ({ isValid: true });

describe("validatePassword", () => {
  describe("Empty or falsy input", () => {
    /**
     * @description Should return invalid result for empty string
     * @scenario Empty string should trigger validation error
     * @expected Error message: "Пароль обязателен для заполнения"
     */
    it("should return invalid for empty string", () => {
      expect(validatePassword("")).toEqual(invalid(ERRORS.REQUIRED));
    });

    /**
     * @description Should return invalid for whitespace-only string
     * @scenario String containing only spaces (less than 6 chars)
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for whitespace-only string", () => {
      expect(validatePassword("   ")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for tab characters only
     * @scenario String containing only tabs (less than 6 chars)
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for tab-only string", () => {
      expect(validatePassword("\t")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for newline characters only
     * @scenario String containing only newlines (less than 6 chars)
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for newline-only string", () => {
      expect(validatePassword("\n")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for mixed whitespace
     * @scenario String containing spaces and tabs (less than 6 chars)
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for mixed whitespace string", () => {
      expect(validatePassword(" \t  ")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });
  });

  describe("Password too short (less than 6 characters)", () => {
    /**
     * @description Should return invalid for single character
     * @scenario Password with only 1 character should trigger validation error
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for single character", () => {
      expect(validatePassword("A")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for two characters
     * @scenario Password with only 2 characters should trigger validation error
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for two characters", () => {
      expect(validatePassword("Ab")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for three characters
     * @scenario Password with only 3 characters should trigger validation error
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for three characters", () => {
      expect(validatePassword("Ab1")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for four characters
     * @scenario Password with only 4 characters should trigger validation error
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for four characters", () => {
      expect(validatePassword("Ab1!")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for five characters
     * @scenario Password with only 5 characters should trigger validation error
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for five characters", () => {
      expect(validatePassword("Ab1!x")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });
  });

  describe("Missing uppercase letter", () => {
    /**
     * @description Should return invalid for password without uppercase
     * @scenario Password without uppercase letter should trigger validation error
     * @expected Error message: "Пароль должен содержать хотя бы одну заглавную букву"
     */
    it("should return invalid for password without uppercase", () => {
      expect(validatePassword("password1!")).toEqual(invalid(ERRORS.UPPERCASE));
    });

    /**
     * @description Should return invalid for all lowercase
     * @scenario All lowercase password should trigger validation error
     * @expected Error message: "Пароль должен содержать хотя бы одну заглавную букву"
     */
    it("should return invalid for all lowercase", () => {
      expect(validatePassword("pass123!")).toEqual(invalid(ERRORS.UPPERCASE));
    });

    /**
     * @description Should return invalid for digits and special chars only
     * @scenario Password with only digits and special chars should trigger error
     * @expected Error message: "Пароль должен содержать хотя бы одну заглавную букву"
     */
    it("should return invalid for digits and special chars only", () => {
      expect(validatePassword("123456!")).toEqual(invalid(ERRORS.UPPERCASE));
    });
  });

  describe("Missing digit", () => {
    /**
     * @description Should return invalid for password without digit
     * @scenario Password without digit should trigger validation error
     * @expected Error message: "Пароль должен содержать хотя бы одну цифру"
     */
    it("should return invalid for password without digit", () => {
      expect(validatePassword("Password!")).toEqual(invalid(ERRORS.DIGIT));
    });

    /**
     * @description Should return invalid for password with letters only
     * @scenario Password with only letters should trigger validation error
     * @expected Error message: "Пароль должен содержать хотя бы одну цифру"
     */
    it("should return invalid for letters only", () => {
      expect(validatePassword("Password")).toEqual(invalid(ERRORS.DIGIT));
    });

    /**
     * @description Should return invalid for password with special chars only
     * @scenario Password with only special characters (less than 6) should fail
     * @expected Error message: "Пароль должен содержать не менее 6 символов"
     */
    it("should return invalid for special chars only (short)", () => {
      expect(validatePassword("P@ss!")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });
  });

  describe("Missing special character", () => {
    /**
     * @description Should return invalid for password without special char
     * @scenario Password without special character should trigger error
     * @expected Error message: "Пароль должен содержать хотя бы один специальный символ"
     */
    it("should return invalid without special character", () => {
      expect(validatePassword("Password1")).toEqual(invalid(ERRORS.SPECIAL));
    });

    /**
     * @description Should return invalid for password with only letters and digits
     * @scenario Password without special chars should trigger validation error
     * @expected Error message: "Пароль должен содержать хотя бы один специальный символ"
     */
    it("should return invalid for letters and digits only", () => {
      expect(validatePassword("Password12")).toEqual(invalid(ERRORS.SPECIAL));
    });

    /**
     * @description Should return invalid for password with only letters (6+ chars)
     * @scenario Password with only letters (6+ chars) should trigger validation error
     * @expected Error message: "Пароль должен содержать хотя бы одну цифру"
     */
    it("should return invalid for letters only (6+ chars)", () => {
      expect(validatePassword("Password")).toEqual(invalid(ERRORS.DIGIT));
    });
  });

  describe("Contains forbidden words", () => {
    /**
     * @description Should return invalid for password containing 'admin'
     * @scenario Password with 'admin' should trigger validation error
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for password containing admin", () => {
      expect(validatePassword("Admin123!")).toEqual(invalid(ERRORS.FORBIDDEN));
    });

    /**
     * @description Should return invalid for password containing 'password'
     * @scenario Password with 'password' should trigger validation error
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for password containing password", () => {
      expect(validatePassword("Password123!")).toEqual(
        invalid(ERRORS.FORBIDDEN),
      );
    });

    /**
     * @description Should return invalid for password with 'ADMIN' uppercase
     * @scenario Password with uppercase 'ADMIN' should trigger validation error
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for uppercase ADMIN", () => {
      expect(validatePassword("ADMIN123!")).toEqual(invalid(ERRORS.FORBIDDEN));
    });

    /**
     * @description Should return invalid for password with 'PASSWORD' uppercase
     * @scenario Password with uppercase 'PASSWORD' should trigger error
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for uppercase PASSWORD", () => {
      expect(validatePassword("PASSWORD123!")).toEqual(
        invalid(ERRORS.FORBIDDEN),
      );
    });

    /**
     * @description Should return invalid for password with mixed case Admin
     * @scenario Password with 'Admin' mixed case should trigger validation error
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for mixed case Admin", () => {
      expect(validatePassword("AdMiN123!")).toEqual(invalid(ERRORS.FORBIDDEN));
    });

    /**
     * @description Should return invalid for password with mixed case Password
     * @scenario Password with 'Password' mixed case should trigger error
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for mixed case Password", () => {
      expect(validatePassword("PaSsWoRd123!")).toEqual(
        invalid(ERRORS.FORBIDDEN),
      );
    });

    /**
     * @description Should return invalid for password containing admin as part
     * @scenario Password with 'admin' as part of longer string should fail
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for admin as part of longer string", () => {
      expect(validatePassword("MyAdmin123!")).toEqual(
        invalid(ERRORS.FORBIDDEN),
      );
    });

    /**
     * @description Should return invalid for password containing password as part
     * @scenario Password with 'password' as part of longer string should fail
     * @expected Error message: "Пароль не должен содержать 'admin' или 'password'"
     */
    it("should return invalid for password as part of longer string", () => {
      expect(validatePassword("MyPassword123!")).toEqual(
        invalid(ERRORS.FORBIDDEN),
      );
    });
  });

  describe("Valid password formats", () => {
    /**
     * @description Should return valid for minimal valid password
     * @scenario Password with exactly 6 chars meeting all criteria should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for minimal valid password", () => {
      expect(validatePassword("Pass1!")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with multiple special chars
     * @scenario Password with multiple special characters should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with multiple special chars", () => {
      expect(validatePassword("Test12!@#")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with common special char
     * @scenario Password with common special character (!) should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with exclamation mark", () => {
      expect(validatePassword("Test123!")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with at symbol
     * @scenario Password with @ symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with at symbol", () => {
      expect(validatePassword("Test123@")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with hash symbol
     * @scenario Password with # symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with hash symbol", () => {
      expect(validatePassword("Test123#")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with dollar sign
     * @scenario Password with $ symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with dollar sign", () => {
      expect(validatePassword("Test123$")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with percent sign
     * @scenario Password with % symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with percent sign", () => {
      expect(validatePassword("Test123%")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with ampersand
     * @scenario Password with & symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with ampersand", () => {
      expect(validatePassword("Test123&")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with asterisk
     * @scenario Password with * symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with asterisk", () => {
      expect(validatePassword("Test123*")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with question mark
     * @scenario Password with ? symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with question mark", () => {
      expect(validatePassword("Test123?")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with plus sign
     * @scenario Password with + symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with plus sign", () => {
      expect(validatePassword("Test123+")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with equals sign
     * @scenario Password with = symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with equals sign", () => {
      expect(validatePassword("Test123=")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with underscore
     * @scenario Password with _ symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with underscore", () => {
      expect(validatePassword("Test123_")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with hyphen
     * @scenario Password with - symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with hyphen", () => {
      expect(validatePassword("Test123-")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with pipe symbol
     * @scenario Password with | symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with pipe symbol", () => {
      expect(validatePassword("Test123|")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with colon
     * @scenario Password with : symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with colon", () => {
      expect(validatePassword("Test123:")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with semicolon
     * @scenario Password with ; symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with semicolon", () => {
      expect(validatePassword("Test123;")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with quotes
     * @scenario Password with quotes should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with quotes", () => {
      expect(validatePassword('Test123"')).toEqual(valid());
    });

    /**
     * @description Should return valid for password with brackets
     * @scenario Password with brackets should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with brackets", () => {
      expect(validatePassword("Test12[]")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with braces
     * @scenario Password with braces should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with braces", () => {
      expect(validatePassword("Test12{}")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with slash
     * @scenario Password with / symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with slash", () => {
      expect(validatePassword("Test12/")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with backslash
     * @scenario Password with \ symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with backslash", () => {
      expect(validatePassword("Test12\\")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with less than symbol
     * @scenario Password with < symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with less than symbol", () => {
      expect(validatePassword("Test12<")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with greater than symbol
     * @scenario Password with > symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with greater than symbol", () => {
      expect(validatePassword("Test12>")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with tilde
     * @scenario Password with ~ symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with tilde", () => {
      expect(validatePassword("Test12~")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with grave accent
     * @scenario Password with ` symbol should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with grave accent", () => {
      expect(validatePassword("Test12`")).toEqual(valid());
    });

    /**
     * @description Should return valid for long password
     * @scenario Password with many characters should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for long password", () => {
      expect(validatePassword("SecurePass123!@#")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with multiple digits
     * @scenario Password with multiple digits should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with multiple digits", () => {
      expect(validatePassword("Secure12!")).toEqual(valid());
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should return valid for password at minimum length (exactly 6)
     * @scenario Password at exactly 6 chars meeting all criteria should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password at minimum length", () => {
      expect(validatePassword("Ab1!xy")).toEqual(valid());
    });

    /**
     * @description Should return valid for password with zero in it
     * @scenario Password containing 0 should be valid
     * @expected isValid: true, no error message
     */
    it("should return valid for password with zero", () => {
      expect(validatePassword("Pass0rd!")).toEqual(valid());
    });

    /**
     * @description Should return invalid for password missing uppercase but has all
     * @scenario Password without uppercase even with all other criteria should fail
     * @expected Error message about missing uppercase
     */
    it("should prioritize uppercase error over other checks", () => {
      expect(validatePassword("pass1!")).toEqual(invalid(ERRORS.UPPERCASE));
    });

    /**
     * @description Should return invalid for password missing digit but has all
     * @scenario Password without digit even with all other criteria should fail
     * @expected Error message about missing digit
     */
    it("should prioritize digit error over other checks", () => {
      expect(validatePassword("Secure!")).toEqual(invalid(ERRORS.DIGIT));
    });

    /**
     * @description Should return invalid for password missing special but has all
     * @scenario Password without special char (6+ chars, uppercase, digit) should fail
     * @expected Error message about missing special character
     */
    it("should return missing special char error for valid otherwise", () => {
      expect(validatePassword("Secure1")).toEqual(invalid(ERRORS.SPECIAL));
    });

    /**
     * @description Should return invalid for password with admin at less than 6 chars
     * @scenario Short password containing admin should fail length check first
     * @expected Error message about minimum length
     */
    it("should return length error before detecting admin in short password", () => {
      expect(validatePassword("admin")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });

    /**
     * @description Should return invalid for password with password at less than 6 chars
     * @scenario Short password containing password should fail length check first
     * @expected Error message about minimum length
     */
    it("should return length error before detecting password in short password", () => {
      expect(validatePassword("pass")).toEqual(invalid(ERRORS.MIN_LENGTH));
    });
  });
});
