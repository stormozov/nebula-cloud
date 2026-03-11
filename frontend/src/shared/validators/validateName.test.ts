import { describe, expect, it } from "vitest";

import { validateName } from "./validateName";

describe("validateName", () => {
  describe("Empty or whitespace-only input", () => {
    /**
     * @description Should return invalid result for empty string
     * @scenario Empty string should trigger validation error
     * @expected Error message: "Имя обязательно для заполнения"
     */
    it("should return invalid for empty string", () => {
      const result = validateName("");

      const expected = {
        isValid: false,
        error: "Имя обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for whitespace-only string
     * @scenario String containing only spaces should trigger validation error
     * @expected Error message: "Имя обязательно для заполнения"
     */
    it("should return invalid for whitespace-only string", () => {
      const result = validateName("   ");

      const expected = {
        isValid: false,
        error: "Имя обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for tab characters only
     * @scenario String containing only tabs should trigger validation error
     * @expected Error message: "Имя обязательно для заполнения"
     */
    it("should return invalid for tab-only string", () => {
      const result = validateName("\t");

      const expected = {
        isValid: false,
        error: "Имя обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for mixed whitespace
     * @scenario String containing spaces and tabs should trigger validation error
     * @expected Error message: "Имя обязательно для заполнения"
     */
    it("should return invalid for mixed whitespace string", () => {
      const result = validateName(" \t  ");

      const expected = {
        isValid: false,
        error: "Имя обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for newline characters only
     * @scenario String containing only newlines should trigger validation error
     * @expected Error message: "Имя обязательно для заполнения"
     */
    it("should return invalid for newline-only string", () => {
      const result = validateName("\n");

      const expected = {
        isValid: false,
        error: "Имя обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Name too short (less than 2 characters)", () => {
    /**
     * @description Should return invalid for single character name
     * @scenario Name with only 1 character should trigger validation error
     * @expected Error message: "Имя должно содержать не менее 2 символов"
     */
    it("should return invalid for single character", () => {
      const result = validateName("A");

      const expected = {
        isValid: false,
        error: "Имя должно содержать не менее 2 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for single Cyrillic character
     * @scenario Name with only 1 Cyrillic character should trigger validation error
     * @expected Error message: "Имя должно содержать не менее 2 символов"
     */
    it("should return invalid for single Cyrillic character", () => {
      const result = validateName("А");

      const expected = {
        isValid: false,
        error: "Имя должно содержать не менее 2 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for single character with spaces
     * @scenario Name with spaces around single character should trigger validation error after trim
     * @expected Error message: "Имя должно содержать не менее 2 символов"
     */
    it("should return invalid for single character with surrounding spaces", () => {
      const result = validateName(" A ");

      const expected = {
        isValid: false,
        error: "Имя должно содержать не менее 2 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name with only hyphen
     * @scenario Name containing only hyphen should trigger validation error
     * @expected Error message: "Имя должно содержать не менее 2 символов"
     */
    it("should return invalid for hyphen only", () => {
      const result = validateName("-");

      const expected = {
        isValid: false,
        error: "Имя должно содержать не менее 2 символов",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid characters in name", () => {
    /**
     * @description Should return invalid for name containing numbers
     * @scenario Name with numeric characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with numbers", () => {
      const result = validateName("John123");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing special characters
     * @scenario Name with special characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with special characters", () => {
      const result = validateName("John@Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing underscores
     * @scenario Name with underscore characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with underscores", () => {
      const result = validateName("John_Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing parentheses
     * @scenario Name with parentheses should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with parentheses", () => {
      const result = validateName("John (Doe)");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing brackets
     * @scenario Name with square brackets should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with brackets", () => {
      const result = validateName("John[Doe]");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing punctuation
     * @scenario Name with periods should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with periods", () => {
      const result = validateName("John.Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing quotes
     * @scenario Name with quotation marks should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with quotes", () => {
      const result = validateName('John "Doe"');

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing slashes
     * @scenario Name with forward slashes should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with slashes", () => {
      const result = validateName("John/Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing backslashes
     * @scenario Name with backslashes should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with backslashes", () => {
      const result = validateName("John\\Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing pipes
     * @scenario Name with pipe characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with pipes", () => {
      const result = validateName("John|Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing at symbol
     * @scenario Name with @ symbol should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with at symbol", () => {
      const result = validateName("John@Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing hashtags
     * @scenario Name with # characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with hashtags", () => {
      const result = validateName("John#Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing dollar sign
     * @scenario Name with $ character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with dollar sign", () => {
      const result = validateName("John$Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing percent sign
     * @scenario Name with % character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with percent sign", () => {
      const result = validateName("John%Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing ampersand
     * @scenario Name with & character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with ampersand", () => {
      const result = validateName("John&Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing asterisks
     * @scenario Name with * character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with asterisks", () => {
      const result = validateName("John*Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing plus sign
     * @scenario Name with + character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with plus sign", () => {
      const result = validateName("John+Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing equals sign
     * @scenario Name with = character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with equals sign", () => {
      const result = validateName("John=Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing question mark
     * @scenario Name with ? character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with question mark", () => {
      const result = validateName("John?Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing exclamation mark
     * @scenario Name with ! character should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with exclamation mark", () => {
      const result = validateName("John!Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing emoji
     * @scenario Name with emoji characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with emoji", () => {
      const result = validateName("John😀Doe");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing Chinese characters
     * @scenario Name with Chinese characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with Chinese characters", () => {
      const result = validateName("约翰");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing Japanese characters
     * @scenario Name with Japanese characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with Japanese characters", () => {
      const result = validateName("田中");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name containing Arabic characters
     * @scenario Name with Arabic characters should trigger validation error
     * @expected Error message: "Имя должно содержать только буквы"
     */
    it("should return invalid for name with Arabic characters", () => {
      const result = validateName("محمد");

      const expected = {
        isValid: false,
        error: "Имя должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Valid name formats", () => {
    /**
     * @description Should return valid for simple Latin name
     * @scenario Standard Latin name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for simple Latin name", () => {
      const result = validateName("John");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for Latin first and last name
     * @scenario Two-word Latin name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for Latin first and last name", () => {
      const result = validateName("John Doe");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for simple Cyrillic name
     * @scenario Standard Cyrillic name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for simple Cyrillic name", () => {
      const result = validateName("Иван");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for Cyrillic first and last name
     * @scenario Two-word Cyrillic name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for Cyrillic first and last name", () => {
      const result = validateName("Иван Иванов");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for Cyrillic name with ё character
     * @scenario Name with Cyrillic ё should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for Cyrillic name with ё", () => {
      const result = validateName("Алёна");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for Cyrillic name with Ё character
     * @scenario Name with uppercase Cyrillic Ё should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for Cyrillic name with Ё", () => {
      const result = validateName("Ёлкин");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with hyphen
     * @scenario Name containing hyphen should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for name with hyphen", () => {
      const result = validateName("Мария- Анна");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for hyphenated last name
     * @scenario Double-barreled name with hyphen should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for hyphenated last name", () => {
      const result = validateName("Иван Петров-Водкин");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with multiple spaces
     * @scenario Name with multiple spaces between words should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for name with multiple spaces", () => {
      const result = validateName("John    Doe");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with exactly 2 characters
     * @scenario Name with exactly 2 characters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for name with exactly 2 characters", () => {
      const result = validateName("Ан");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for long name
     * @scenario Name with many characters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for long name", () => {
      const result = validateName("Александрович");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for uppercase Latin name
     * @scenario All uppercase Latin name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for uppercase Latin name", () => {
      const result = validateName("JOHN DOE");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for uppercase Cyrillic name
     * @scenario All uppercase Cyrillic name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for uppercase Cyrillic name", () => {
      const result = validateName("ИВАН ИВАНОВ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for mixed case Latin name
     * @scenario Mixed case Latin name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for mixed case Latin name", () => {
      const result = validateName("John Doe");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for mixed case Cyrillic name
     * @scenario Mixed case Cyrillic name should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for mixed case Cyrillic name", () => {
      const result = validateName("Иван Иванов");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Name with surrounding whitespace", () => {
    /**
     * @description Should return valid for name with leading spaces
     * @scenario Name with leading spaces should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for name with leading spaces", () => {
      const result = validateName("  Иван");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with trailing spaces
     * @scenario Name with trailing spaces should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for name with trailing spaces", () => {
      const result = validateName("Иван  ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with surrounding spaces
     * @scenario Name with spaces on both sides should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for name with surrounding spaces", () => {
      const result = validateName("  Иван  ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with leading and trailing tabs
     * @scenario Name with tabs on both sides should be validated after trimming
     * @expected isValid: true, no error message
     */
    it("should return valid for name with tabs", () => {
      const result = validateName("\tИван\t");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for name with leading whitespace but too short
     * @scenario Name with leading spaces that results in less than 2 chars after trim should fail
     * @expected Error message: "Имя должно содержать не менее 2 символов"
     */
    it("should return invalid for whitespace-padded single character", () => {
      const result = validateName("  A  ");

      const expected = {
        isValid: false,
        error: "Имя должно содержать не менее 2 символов",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Custom field name", () => {
    /**
     * @description Should return error with custom field name for empty string
     * @scenario Empty string with custom field name should show custom error message
     * @expected Error message should contain custom field name (function uses neuter gender)
     */
    it("should return error with custom field name for empty string", () => {
      const result = validateName("", "Фамилия");

      const expected = {
        isValid: false,
        error: "Фамилия обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return error with custom field name for too short
     * @scenario Name too short with custom field name should show custom error message
     * @expected Error message should contain custom field name
     */
    it("should return error with custom field name for too short", () => {
      const result = validateName("А", "Фамилия");

      const expected = {
        isValid: false,
        error: "Фамилия должно содержать не менее 2 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return error with custom field name for invalid characters
     * @scenario Name with invalid characters and custom field name should show custom error message
     * @expected Error message should contain custom field name
     */
    it("should return error with custom field name for invalid characters", () => {
      const result = validateName("Иван123", "Фамилия");

      const expected = {
        isValid: false,
        error: "Фамилия должно содержать только буквы",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for valid name with custom field name
     * @scenario Valid name with custom field name should return valid
     * @expected isValid: true, no error message
     */
    it("should return valid for valid name with custom field name", () => {
      const result = validateName("Иванов", "Фамилия");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return error with empty custom field name
     * @scenario Empty string with empty custom field name should handle gracefully
     * @expected Error message should show empty field name in message (function uses neuter gender)
     */
    it("should handle empty custom field name", () => {
      const result = validateName("", "");

      const expected = {
        isValid: false,
        error: " обязательно для заполнения",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should return valid for name with hyphen at start
     * @scenario Name starting with hyphen should be accepted (edge case)
     * @expected isValid: true, no error message
     */
    it("should return valid for name starting with hyphen", () => {
      const result = validateName("-Иван");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with hyphen at end
     * @scenario Name ending with hyphen should be accepted (edge case)
     * @expected isValid: true, no error message
     */
    it("should return valid for name ending with hyphen", () => {
      const result = validateName("Иван-");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with multiple consecutive hyphens
     * @scenario Name with multiple hyphens should be accepted (edge case)
     * @expected isValid: true, no error message
     */
    it("should return valid for name with multiple hyphens", () => {
      const result = validateName("Джон--Смит");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for single word with spaces around
     * @scenario Single valid word with surrounding spaces should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for single word with surrounding spaces", () => {
      const result = validateName("   Иван   ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with only letters (minimum length)
     * @scenario Exactly 2 letters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for two-letter name", () => {
      const result = validateName("Аб");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for name with russian yo character
     * @scenario Name with ё should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for name with russian yo", () => {
      const result = validateName("Лёша");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });
});
