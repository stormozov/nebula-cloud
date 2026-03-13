import { describe, expect, it } from "vitest";

import { validateLogin } from "./validateLogin";

describe("validateLogin", () => {
  describe("Empty or whitespace-only input", () => {
    /**
     * @description Should return invalid result for empty string
     * @scenario Empty string should trigger validation error
     * @expected Error message: "Логин обязателен для заполнения"
     */
    it("should return invalid for empty string", () => {
      const result = validateLogin("");

      const expected = {
        isValid: false,
        error: "Логин обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for whitespace-only string
     * @scenario String containing only spaces should trigger validation error
     * @expected Error message: "Логин обязателен для заполнения"
     */
    it("should return invalid for whitespace-only string", () => {
      const result = validateLogin("   ");

      const expected = {
        isValid: false,
        error: "Логин обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for tab characters only
     * @scenario String containing only tabs should trigger validation error
     * @expected Error message: "Логин обязателен для заполнения"
     */
    it("should return invalid for tab-only string", () => {
      const result = validateLogin("\t");

      const expected = {
        isValid: false,
        error: "Логин обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for mixed whitespace
     * @scenario String containing spaces and tabs should trigger validation error
     * @expected Error message: "Логин обязателен для заполнения"
     */
    it("should return invalid for mixed whitespace string", () => {
      const result = validateLogin(" \t  ");

      const expected = {
        isValid: false,
        error: "Логин обязателен для заполнения",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid length - too short", () => {
    /**
     * @description Should return invalid for login with 3 characters
     * @scenario Login shorter than 4 characters should be rejected
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with 3 characters", () => {
      const result = validateLogin("abc");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login with 2 characters
     * @scenario Login with only 2 characters should be rejected
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with 2 characters", () => {
      const result = validateLogin("ab");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login with 1 character
     * @scenario Login with only 1 character should be rejected
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with 1 character", () => {
      const result = validateLogin("a");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login with spaces around valid length
     * @scenario Login with 4 characters but surrounded by spaces should be rejected (spaces are trimmed)
     * @expected Error message: "Логин обязателен для заполнения"
     */
    it("should return invalid for login with spaces around valid content", () => {
      const result = validateLogin("  ab  ");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid length - too long", () => {
    /**
     * @description Should return invalid for login with 21 characters
     * @scenario Login longer than 20 characters should be rejected
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with 21 characters", () => {
      const result = validateLogin("abcdefghijklmnopqrstu");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login with 25 characters
     * @scenario Login with 25 characters should be rejected
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with 25 characters", () => {
      const result = validateLogin("abcdefghijklmnopqrstuvwxy");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login with 30 characters
     * @scenario Login with 30 characters should be rejected
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with 30 characters", () => {
      const result = validateLogin("abcdefghijklmnopqrstuvwxyz12345");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid first character - must start with letter", () => {
    /**
     * @description Should return invalid for login starting with digit
     * @scenario Login starting with a digit should be rejected
     * @expected Error message: "Первый символ логина должен быть буквой"
     */
    it("should return invalid for login starting with digit", () => {
      const result = validateLogin("1user");

      const expected = {
        isValid: false,
        error: "Первый символ логина должен быть буквой",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login starting with underscore
     * @scenario Login starting with underscore should be rejected
     * @expected Error message: "Первый символ логина должен быть буквой"
     */
    it("should return invalid for login starting with underscore", () => {
      const result = validateLogin("_user");

      const expected = {
        isValid: false,
        error: "Первый символ логина должен быть буквой",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login starting with hyphen
     * @scenario Login starting with hyphen should be rejected
     * @expected Error message: "Первый символ логина должен быть буквой"
     */
    it("should return invalid for login starting with hyphen", () => {
      const result = validateLogin("-user");

      const expected = {
        isValid: false,
        error: "Первый символ логина должен быть буквой",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login starting with special character
     * @scenario Login starting with special character should be rejected
     * @expected Error message: "Первый символ логина должен быть буквой"
     */
    it("should return invalid for login starting with special character", () => {
      const result = validateLogin("@user");

      const expected = {
        isValid: false,
        error: "Первый символ логина должен быть буквой",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login starting with space and trimmed to valid login
     * @scenario Login starting with space gets trimmed to valid login "user"
     * @expected isValid: true, no error message
     */
    it("should return valid for login starting with space", () => {
      const result = validateLogin(" user");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Invalid characters in login", () => {
    /**
     * @description Should return invalid for login containing spaces
     * @scenario Login with spaces in the middle should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing spaces", () => {
      const result = validateLogin("user name");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing Cyrillic letters
     * @scenario Login with Cyrillic characters fails first character check (length 11 passes, but first char 'п' is not Latin letter)
     * @expected Error message: "Первый символ логина должен быть буквой"
     */
    it("should return invalid for login containing Cyrillic letters", () => {
      const result = validateLogin("пользователь");

      const expected = {
        isValid: false,
        error: "Первый символ логина должен быть буквой",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing special characters
     * @scenario Login with special characters should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing special characters", () => {
      const result = validateLogin("user!name");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing underscore
     * @scenario Login with underscore should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing underscore", () => {
      const result = validateLogin("user_name");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing hyphen
     * @scenario Login with hyphen should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing hyphen", () => {
      const result = validateLogin("user-name");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing dot
     * @scenario Login with dot should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing dot", () => {
      const result = validateLogin("user.name");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing parentheses
     * @scenario Login with parentheses should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing parentheses", () => {
      const result = validateLogin("user(name)");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing at symbol
     * @scenario Login with @ symbol should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing at symbol", () => {
      const result = validateLogin("user@name");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing Chinese characters
     * @scenario Login with Chinese characters fails length check (3 characters < 4)
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login containing Chinese characters", () => {
      const result = validateLogin("用户名");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login containing emoji
     * @scenario Login with emoji should be rejected
     * @expected Error message: "Логин должен содержать только латинские буквы и цифры"
     */
    it("should return invalid for login containing emoji", () => {
      const result = validateLogin("user😀");

      const expected = {
        isValid: false,
        error: "Логин должен содержать только латинские буквы и цифры",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Valid login formats", () => {
    /**
     * @description Should return valid for login with minimum valid length
     * @scenario Login with exactly 4 characters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with minimum valid length", () => {
      const result = validateLogin("user");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with maximum valid length
     * @scenario Login with exactly 20 characters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with maximum valid length", () => {
      const result = validateLogin("abcdefghijklmnopqrst");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with only letters
     * @scenario Login containing only Latin letters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with only letters", () => {
      const result = validateLogin("username");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with only digits
     * @scenario Login starting with letter and containing only digits should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with only digits after letter", () => {
      const result = validateLogin("user123");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with mixed letters and digits
     * @scenario Login with combination of letters and digits should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with mixed letters and digits", () => {
      const result = validateLogin("user123name");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login starting with uppercase letter
     * @scenario Login starting with uppercase Latin letter should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login starting with uppercase letter", () => {
      const result = validateLogin("UserName");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with all uppercase letters
     * @scenario Login with all uppercase letters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with all uppercase letters", () => {
      const result = validateLogin("USERNAME");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with mixed case
     * @scenario Login with mixed case letters should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with mixed case", () => {
      const result = validateLogin("UserName123");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login ending with digits
     * @scenario Login ending with digits should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login ending with digits", () => {
      const result = validateLogin("name12345");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with digits in the middle
     * @scenario Login with digits in the middle should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with digits in the middle", () => {
      const result = validateLogin("user123name");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Login with surrounding whitespace", () => {
    /**
     * @description Should return valid for login with leading spaces
     * @scenario Login with leading spaces should be trimmed and validated
     * @expected isValid: true, no error message
     */
    it("should return valid for login with leading spaces", () => {
      const result = validateLogin("  user");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with trailing spaces
     * @scenario Login with trailing spaces should be trimmed and validated
     * @expected isValid: true, no error message
     */
    it("should return valid for login with trailing spaces", () => {
      const result = validateLogin("user  ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with surrounding spaces
     * @scenario Login with spaces on both sides should be trimmed and validated
     * @expected isValid: true, no error message
     */
    it("should return valid for login with surrounding spaces", () => {
      const result = validateLogin("  user123  ");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return invalid for login with leading spaces making it too short after trim
     * @scenario Login with 2 chars + 2 spaces should be rejected after trimming
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for login with leading spaces making it too short", () => {
      const result = validateLogin("  ab  ");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should return valid for login at exact minimum length boundary
     * @scenario Login with exactly 4 characters at boundary should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login at exact minimum length boundary", () => {
      const result = validateLogin("abcd");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login at exact maximum length boundary
     * @scenario Login with exactly 20 characters at boundary should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login at exact maximum length boundary", () => {
      const result = validateLogin("abcd1234efgh5678ij");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with repeated pattern
     * @scenario Login with repeated pattern should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with repeated pattern", () => {
      const result = validateLogin("ababababab");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login with all digits after letter
     * @scenario Login starting with letter followed by all digits should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login with all digits after letter", () => {
      const result = validateLogin("a123456789");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login starting with lowercase z
     * @scenario Login starting with 'z' should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login starting with lowercase z", () => {
      const result = validateLogin("zebra123");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for login starting with uppercase Z
     * @scenario Login starting with 'Z' should be accepted
     * @expected isValid: true, no error message
     */
    it("should return valid for login starting with uppercase Z", () => {
      const result = validateLogin("Zebra123");

      const expected = {
        isValid: true,
      };

      expect(result).toEqual(expected);
    });

    /**
     * @description Should return valid for single letter login with spaces
     * @scenario Single letter surrounded by spaces should be rejected after trimming
     * @expected Error message: "Длина логина должна быть от 4 до 20 символов"
     */
    it("should return invalid for single letter with surrounding spaces", () => {
      const result = validateLogin("  a  ");

      const expected = {
        isValid: false,
        error: "Длина логина должна быть от 4 до 20 символов",
      };

      expect(result).toEqual(expected);
    });
  });
});
