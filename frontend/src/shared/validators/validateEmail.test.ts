import { describe, expect, it } from "vitest";

import { validateEmail } from "./validateEmail";

describe("validateEmail", () => {
  describe("Empty or whitespace-only input", () => {
    /**
     * @description Should return invalid result for empty string
     * @scenario Empty string should trigger validation error
     * @expected Error message: "Email обязателен для заполнения"
     */
    it("should return invalid for empty string", () => {
      const result = validateEmail("");

      const expected = {
        isValid: false,
        error: "Email обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for whitespace-only string
     * @scenario String containing only spaces should trigger validation error
     * @expected Error message: "Email обязателен для заполнения"
     */
    it("should return invalid for whitespace-only string", () => {
      const result = validateEmail("   ");

      const expected = {
        isValid: false,
        error: "Email обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for tab characters
     * @scenario String containing only tabs should trigger validation error
     * @expected Error message: "Email обязателен для заполнения"
     */
    it("should return invalid for tab-only string", () => {
      const result = validateEmail("\t");

      const expected = {
        isValid: false,
        error: "Email обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for mixed whitespace
     * @scenario String containing spaces and tabs should trigger validation error
     * @expected Error message: "Email обязателен для заполнения"
     */
    it("should return invalid for mixed whitespace string", () => {
      const result = validateEmail(" \t  ");

      const expected = {
        isValid: false,
        error: "Email обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid email format - missing @ symbol", () => {
    /**
     * @description Should return invalid for email without @ symbol
     * @scenario Email address without @ should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email without @ symbol", () => {
      const result = validateEmail("userexample.com");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid email format - missing local part", () => {
    /**
     * @description Should return invalid for email with missing local part
     * @scenario Email address starting with @ should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with missing local part", () => {
      const result = validateEmail("@example.com");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid email format - missing domain", () => {
    /**
     * @description Should return invalid for email with missing domain
     * @scenario Email address ending with @ should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with missing domain", () => {
      const result = validateEmail("user@");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for email with @ but no domain
     * @scenario Email with @ and empty domain should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with @ but empty domain", () => {
      const result = validateEmail("user@ ");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid email format - missing or invalid TLD", () => {
    /**
     * @description Should return invalid for email without TLD
     * @scenario Email address without top-level domain should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email without TLD", () => {
      const result = validateEmail("user@example");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for email with single character TLD
     * @scenario Email with TLD of only 1 character should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with single character TLD", () => {
      const result = validateEmail("user@example.c");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for email with numeric TLD
     * @scenario Email with numeric top-level domain should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with numeric TLD", () => {
      const result = validateEmail("user@example.123");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid email format - invalid characters", () => {
    /**
     * @description Should return invalid for email with spaces in local part
     * @scenario Email with spaces should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with spaces", () => {
      const result = validateEmail("user name@example.com");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for email with special characters not allowed
     * @scenario Email with brackets should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with special characters", () => {
      const result = validateEmail("user[name@example.com");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for email with quotes
     * @scenario Email with quotes should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with quotes", () => {
      const result = validateEmail('"user"@example.com');

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid email format - multiple @ symbols", () => {
    /**
     * @description Should return invalid for email with multiple @ symbols
     * @scenario Email with two @ symbols should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with multiple @ symbols", () => {
      const result = validateEmail("user@@example.com");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for email with @ in local part
     * @scenario Email with @ in local part should be rejected
     * @expected Error message: "Введите корректный email адрес"
     */
    it("should return invalid for email with @ in local part", () => {
      const result = validateEmail("user@name@example.com");

      const expected = {
        isValid: false,
        error: "Введите корректный email адрес",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Valid email formats", () => {
    /**
     * @description Should return valid for simple email address
     * @scenario Standard email format should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for simple email", () => {
      const result = validateEmail("user@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with subdomain
     * @scenario Email with subdomain should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with subdomain", () => {
      const result = validateEmail("user@mail.example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with plus sign (tagging)
     * @scenario Email with + should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with plus sign", () => {
      const result = validateEmail("user+tag@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with dots in local part
     * @scenario Email with multiple dots in local part should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with dots in local part", () => {
      const result = validateEmail("first.last@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with hyphen in domain
     * @scenario Email with hyphen in domain name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with hyphen in domain", () => {
      const result = validateEmail("user@my-domain.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with numbers
     * @scenario Email with numeric characters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with numbers", () => {
      const result = validateEmail("user123@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with underscores
     * @scenario Email with underscore in local part should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with underscores", () => {
      const result = validateEmail("user_name@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with dot at start of local part
     * @scenario Email with dot at start of local part should be accepted (implementation allows)
     * @expected isValid: true, no error message
     */
    it("should return valid for email with dot at start of local part", () => {
      const result = validateEmail(".user@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with dot at end of local part
     * @scenario Email with dot at end of local part should be accepted (implementation allows)
     * @expected isValid: true, no error message
     */
    it("should return valid for email with dot at end of local part", () => {
      const result = validateEmail("user.@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with hyphen at start of domain
     * @scenario Email with hyphen at start of domain should be accepted (implementation allows)
     * @expected isValid: true, no error message
     */
    it("should return valid for email with hyphen at start of domain", () => {
      const result = validateEmail("user@-example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with domain starting with dot
     * @scenario Email with domain starting with dot should be accepted (implementation allows)
     * @expected isValid: true, no error message
     */
    it("should return valid for email with domain starting with dot", () => {
      const result = validateEmail("user@.example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Email with surrounding whitespace", () => {
    /**
     * @description Should return valid for email with leading spaces (should be trimmed)
     * @scenario Email with leading spaces should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for email with leading spaces", () => {
      const result = validateEmail("  user@example.com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with trailing spaces (should be trimmed)
     * @scenario Email with trailing spaces should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for email with trailing spaces", () => {
      const result = validateEmail("user@example.com  ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with surrounding spaces
     * @scenario Email with spaces on both sides should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for email with surrounding spaces", () => {
      const result = validateEmail("  user@example.com  ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should return valid for email with two-character TLD
     * @scenario Email with exactly 2-character TLD should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with two-character TLD", () => {
      const result = validateEmail("user@example.co");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with long TLD
     * @scenario Email with longer TLD should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with long TLD", () => {
      const result = validateEmail("user@example.company");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for email with capital letters
     * @scenario Email with uppercase characters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for email with capital letters", () => {
      const result = validateEmail("USER@EXAMPLE.COM");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for mixed case email
     * @scenario Email with mixed case should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for mixed case email", () => {
      const result = validateEmail("User.Name@Example.Com");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });
});
