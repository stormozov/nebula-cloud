import { describe, expect, it } from "vitest";

import { validateLoginForm } from "./validateLoginForm";

/**
 * Valid test data for login form with all valid fields.
 */
const validFormData = {
  username: "user123",
  password: "SecurePass1!",
};

/**
 * Helper to create expected valid result for a field.
 */
const validField = () => ({ isValid: true });

describe("validateLoginForm", () => {
  describe("Valid login form data", () => {
    /**
     * @description Should return all fields valid when all fields are correct
     * @scenario Submitting a login form with valid data for all fields
     * @expected All fields should have isValid: true
     */
    it("should return all fields valid with correct data", () => {
      const result = validateLoginForm(validFormData);

      expect(result.username).toEqual(validField());
      expect(result.password).toEqual(validField());
    });

    /**
     * @description Should return valid with minimal valid data
     * @scenario Submitting login with minimum valid characters
     * @expected All fields should be valid
     */
    it("should return valid with minimal valid data", () => {
      const minimalData = {
        username: "user",
        password: "Pass1!",
      };

      const result = validateLoginForm(minimalData);

      expect(result.username.isValid).toBe(true);
      expect(result.password.isValid).toBe(true);
    });
  });

  describe("Username field integration with validateLogin", () => {
    /**
     * @description Should return invalid for empty username
     * @scenario Submitting login with empty username field
     * @expected Username should have error: "Логин обязателен для заполнения"
     */
    it("should return invalid for empty username", () => {
      const result = validateLoginForm({
        ...validFormData,
        username: "",
      });

      expect(result.username).toEqual({
        isValid: false,
        error: "Логин обязателен для заполнения",
      });
    });

    /**
     * @description Should return invalid for username that is too short
     * @scenario Submitting login with username less than 4 characters
     * @expected Username should have length error
     */
    it("should return invalid for username that is too short", () => {
      const result = validateLoginForm({
        ...validFormData,
        username: "abc",
      });

      expect(result.username.isValid).toBe(false);
      expect(result.username.error).toBe(
        "Длина логина должна быть от 4 до 20 символов",
      );
    });

    /**
     * @description Should return invalid for username starting with digit
     * @scenario Submitting login with username starting with a digit
     * @expected Username should have error about first character
     */
    it("should return invalid for username starting with digit", () => {
      const result = validateLoginForm({
        ...validFormData,
        username: "1user",
      });

      expect(result.username.isValid).toBe(false);
      expect(result.username.error).toBe(
        "Первый символ логина должен быть буквой",
      );
    });

    /**
     * @description Should return invalid for username with invalid characters
     * @scenario Submitting login with username containing special characters
     * @expected Username should have error about allowed characters
     */
    it("should return invalid for username with special characters", () => {
      const result = validateLoginForm({
        ...validFormData,
        username: "user_name",
      });

      expect(result.username.isValid).toBe(false);
      expect(result.username.error).toBe(
        "Логин должен содержать только латинские буквы и цифры",
      );
    });
  });

  describe("Password field integration with validatePassword", () => {
    /**
     * @description Should return invalid for empty password
     * @scenario Submitting login with empty password field
     * @expected Password should have error: "Пароль обязателен для заполнения"
     */
    it("should return invalid for empty password", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "",
      });

      expect(result.password).toEqual({
        isValid: false,
        error: "Пароль обязателен для заполнения",
      });
    });

    /**
     * @description Should return invalid for password that is too short
     * @scenario Submitting login with password less than 6 characters
     * @expected Password should have error about minimum length
     */
    it("should return invalid for password that is too short", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "Pass1",
      });

      expect(result.password.isValid).toBe(false);
      expect(result.password.error).toBe(
        "Пароль должен содержать не менее 6 символов",
      );
    });

    /**
     * @description Should return invalid for password without uppercase
     * @scenario Submitting login with password without uppercase letter
     * @expected Password should have error about uppercase requirement
     */
    it("should return invalid for password without uppercase", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "password1!",
      });

      expect(result.password.isValid).toBe(false);
      expect(result.password.error).toBe(
        "Пароль должен содержать хотя бы одну заглавную букву",
      );
    });

    /**
     * @description Should return invalid for password without digit
     * @scenario Submitting login with password without digit
     * @expected Password should have error about digit requirement
     */
    it("should return invalid for password without digit", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "Password!",
      });

      expect(result.password.isValid).toBe(false);
      expect(result.password.error).toBe(
        "Пароль должен содержать хотя бы одну цифру",
      );
    });

    /**
     * @description Should return invalid for password without special character
     * @scenario Submitting login with password without special character
     * @expected Password should have error about special character requirement
     */
    it("should return invalid for password without special character", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "Password1",
      });

      expect(result.password.isValid).toBe(false);
      expect(result.password.error).toBe(
        "Пароль должен содержать хотя бы один специальный символ",
      );
    });

    /**
     * @description Should return invalid for password containing forbidden words
     * @scenario Submitting login with password containing 'password'
     * @expected Password should have error about forbidden words
     */
    it("should return invalid for password containing forbidden word", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "Password123!",
      });

      expect(result.password.isValid).toBe(false);
      expect(result.password.error).toBe(
        "Пароль не должен содержать 'admin' или 'password'",
      );
    });
  });

  describe("Return value structure", () => {
    /**
     * @description Should return an object with username and password keys
     * @scenario Validating login form data
     * @expected Result should contain username and password keys
     */
    it("should return an object with username and password keys", () => {
      const result = validateLoginForm(validFormData);

      expect(result).toHaveProperty("username");
      expect(result).toHaveProperty("password");
    });

    /**
     * @description Each validation result should have isValid property
     * @scenario Validating login form data
     * @expected Each field result should have isValid boolean property
     */
    it("should have isValid property in each field result", () => {
      const result = validateLoginForm(validFormData);

      expect(result.username).toHaveProperty("isValid");
      expect(result.password).toHaveProperty("isValid");
    });

    /**
     * @description Invalid field results should have error property
     * @scenario Validating login form with invalid data
     * @expected Each invalid field should have error string property
     */
    it("should have error property in invalid field results", () => {
      const result = validateLoginForm({
        ...validFormData,
        username: "",
      });

      expect(result.username.error).toBeDefined();
      expect(typeof result.username.error).toBe("string");
    });
  });

  describe("Multiple fields validation", () => {
    /**
     * @description Should validate both fields independently
     * @scenario Submitting login with both fields invalid
     * @expected Both invalid fields should have appropriate error messages
     */
    it("should validate both fields independently when both are invalid", () => {
      const result = validateLoginForm({
        username: "",
        password: "",
      });

      // Both fields should be invalid
      expect(result.username.isValid).toBe(false);
      expect(result.password.isValid).toBe(false);
      expect(result.username.error).toBe("Логин обязателен для заполнения");
      expect(result.password.error).toBe("Пароль обязателен для заполнения");
    });

    /**
     * @description Should return partial validity when only username is invalid
     * @scenario Submitting login with valid password but invalid username
     * @expected Only username should have error
     */
    it("should return partial validity when only username is invalid", () => {
      const result = validateLoginForm({
        ...validFormData,
        username: "ab",
      });

      expect(result.username.isValid).toBe(false);
      expect(result.password.isValid).toBe(true);
    });

    /**
     * @description Should return partial validity when only password is invalid
     * @scenario Submitting login with valid username but invalid password
     * @expected Only password should have error
     */
    it("should return partial validity when only password is invalid", () => {
      const result = validateLoginForm({
        ...validFormData,
        password: "short",
      });

      expect(result.username.isValid).toBe(true);
      expect(result.password.isValid).toBe(false);
    });

    /**
     * @description Should allow valid username with various valid password formats
     * @scenario Submitting login with valid username and different valid password formats
     * @expected All valid password formats should be accepted
     */
    it("should accept various valid password formats with valid username", () => {
      const validPasswords = ["Pass1!", "Test12@", "Secure123#", "MyPass1$"];

      validPasswords.forEach((password) => {
        const result = validateLoginForm({
          username: "user123",
          password,
        });

        expect(result.username.isValid).toBe(true);
        expect(result.password.isValid).toBe(true);
      });
    });
  });
});
