import { describe, expect, it } from "vitest";

import { validateRegistrationForm } from "./validateRegistrationForm";

/**
 * Valid test data for registration form with all valid fields.
 */
const validFormData = {
  username: "user123",
  email: "user@example.com",
  password: "SecurePass1!",
  passwordConfirm: "SecurePass1!",
  firstName: "Иван",
  lastName: "Иванов",
};

/**
 * Helper to create expected valid result for a field.
 */
const validField = () => ({ isValid: true });

describe("validateRegistrationForm", () => {
  describe("Valid registration form data", () => {
    /**
     * @description Should return all fields valid when all fields are correct
     * @scenario Submitting a registration form with valid data for all fields
     * @expected All fields should have isValid: true
     */
    it("should return all fields valid with correct data", () => {
      const result = validateRegistrationForm(validFormData);

      expect(result.username).toEqual(validField());
      expect(result.email).toEqual(validField());
      expect(result.password).toEqual(validField());
      expect(result.passwordConfirm).toEqual(validField());
      expect(result.firstName).toEqual(validField());
      expect(result.lastName).toEqual(validField());
    });

    /**
     * @description Should return valid with minimal valid data
     * @scenario Submitting registration with minimum valid characters
     * @expected All fields should be valid
     */
    it("should return valid with minimal valid data", () => {
      const minimalData = {
        username: "user",
        email: "a@b.cd",
        password: "Pass1!",
        passwordConfirm: "Pass1!",
        firstName: "Аа",
        lastName: "Бб",
      };

      const result = validateRegistrationForm(minimalData);

      expect(result.username.isValid).toBe(true);
      expect(result.email.isValid).toBe(true);
      expect(result.password.isValid).toBe(true);
      expect(result.passwordConfirm.isValid).toBe(true);
      expect(result.firstName.isValid).toBe(true);
      expect(result.lastName.isValid).toBe(true);
    });
  });

  describe("Password confirmation integration with password", () => {
    /**
     * @description Should pass password to passwordConfirm validator
     * @scenario Submitting registration with matching passwords
     * @expected PasswordConfirm should be valid when matching
     */
    it("should pass password to passwordConfirm validator for matching passwords", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        password: "MyPassword123!",
        passwordConfirm: "MyPassword123!",
      });

      expect(result.passwordConfirm.isValid).toBe(true);
    });

    /**
     * @description Should pass password to passwordConfirm validator for non-matching
     * @scenario Submitting registration with different passwords
     * @expected PasswordConfirm should be invalid when not matching
     */
    it("should pass password to passwordConfirm validator for non-matching passwords", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        password: "Password123!",
        passwordConfirm: "DifferentPassword123!",
      });

      expect(result.passwordConfirm).toEqual({
        isValid: false,
        error: "Пароли не совпадают",
      });
    });

    /**
     * @description Should return invalid for empty password confirmation
     * @scenario Submitting registration with empty passwordConfirm field
     * @expected PasswordConfirm should have error: "Подтверждение пароля обязательно"
     */
    it("should return invalid for empty password confirmation", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        passwordConfirm: "",
      });

      expect(result.passwordConfirm).toEqual({
        isValid: false,
        error: "Подтверждение пароля обязательно",
      });
    });
  });

  describe("Name field labels integration", () => {
    /**
     * @description Should use 'Имя' label for firstName field
     * @scenario Validating firstName with empty value
     * @expected Error should contain 'Имя' label
     */
    it("should use 'Имя' label for firstName field", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        firstName: "",
      });

      expect(result.firstName.error).toContain("Имя");
    });

    /**
     * @description Should use 'Фамилия' label for lastName field
     * @scenario Validating lastName with empty value
     * @expected Error should contain 'Фамилия' label
     */
    it("should use 'Фамилия' label for lastName field", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        lastName: "",
      });

      expect(result.lastName.error).toContain("Фамилия");
    });
  });

  describe("Return value structure", () => {
    /**
     * @description Should return an object with all expected keys
     * @scenario Validating registration form data
     * @expected Result should contain username, email, password, passwordConfirm, firstName, lastName keys
     */
    it("should return an object with all expected keys", () => {
      const result = validateRegistrationForm(validFormData);

      expect(result).toHaveProperty("username");
      expect(result).toHaveProperty("email");
      expect(result).toHaveProperty("password");
      expect(result).toHaveProperty("passwordConfirm");
      expect(result).toHaveProperty("firstName");
      expect(result).toHaveProperty("lastName");
    });

    /**
     * @description Each validation result should have isValid property
     * @scenario Validating registration form data
     * @expected Each field result should have isValid boolean property
     */
    it("should have isValid property in each field result", () => {
      const result = validateRegistrationForm(validFormData);

      expect(result.username).toHaveProperty("isValid");
      expect(result.email).toHaveProperty("isValid");
      expect(result.password).toHaveProperty("isValid");
      expect(result.passwordConfirm).toHaveProperty("isValid");
      expect(result.firstName).toHaveProperty("isValid");
      expect(result.lastName).toHaveProperty("isValid");
    });

    /**
     * @description Invalid field results should have error property
     * @scenario Validating registration form with invalid data
     * @expected Each invalid field should have error string property
     */
    it("should have error property in invalid field results", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        username: "",
      });

      expect(result.username.error).toBeDefined();
      expect(typeof result.username.error).toBe("string");
    });
  });

  describe("Multiple fields validation", () => {
    /**
     * @description Should validate all fields independently
     * @scenario Submitting registration with multiple invalid fields
     * @expected All invalid fields should have appropriate error messages
     */
    it("should validate all fields independently", () => {
      const result = validateRegistrationForm({
        username: "",
        email: "",
        password: "",
        passwordConfirm: "",
        firstName: "",
        lastName: "",
      });

      // All fields should be invalid
      expect(result.username.isValid).toBe(false);
      expect(result.email.isValid).toBe(false);
      expect(result.password.isValid).toBe(false);
      expect(result.passwordConfirm.isValid).toBe(false);
      expect(result.firstName.isValid).toBe(false);
      expect(result.lastName.isValid).toBe(false);
    });

    /**
     * @description Should return partial validity when some fields are valid
     * @scenario Submitting registration with some valid and some invalid fields
     * @expected Only invalid fields should have errors
     */
    it("should return partial validity when some fields are valid", () => {
      const result = validateRegistrationForm({
        ...validFormData,
        username: "test",
        email: "test@example.com",
        password: "TestPass1!",
        passwordConfirm: "TestPass1!",
        firstName: "Тест",
        lastName: "Тестов",
      });

      // These should be valid
      expect(result.username.isValid).toBe(true);
      expect(result.email.isValid).toBe(true);
      expect(result.password.isValid).toBe(true);
      expect(result.passwordConfirm.isValid).toBe(true);
      expect(result.firstName.isValid).toBe(true);
      expect(result.lastName.isValid).toBe(true);
    });
  });
});

