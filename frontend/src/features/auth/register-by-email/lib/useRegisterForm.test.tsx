import { act, renderHook } from "@testing-library/react";
import type React from "react";
import { useNavigate } from "react-router";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  vi,
} from "vitest";

import { useRegisterMutation } from "@/entities/user";
import { hasFieldErrors, parseDjangoApiErrors } from "@/shared/api";
import type { IValidationResult } from "@/shared/types/validation";
import { isFormValid } from "@/shared/utils";
import { validateRegistrationForm } from "@/shared/validators";

import type { IMockFormEvent } from "./test-helpers";
import type {
  IRegisterFormErrors,
  IRegisterFormTouched,
  IRegisterFormValues,
  IUseRegisterFormProps,
} from "./types";
import { useRegisterForm } from "./useRegisterForm";

// Mock all dependencies at top level
vi.mock("react-router", () => ({
  useNavigate: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  useRegisterMutation: vi.fn(),
}));

vi.mock("@/shared/validators", () => ({
  validateRegistrationForm: vi.fn(),
}));

vi.mock("@/shared/utils", () => ({
  isFormValid: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  parseDjangoApiErrors: vi.fn(),
  hasFieldErrors: vi.fn(),
}));

const mockNavigate: Mock = vi.fn();
const mockRegister: Mock = vi.fn();
const mockOnSuccess: Mock = vi.fn();
const mockOnError: Mock<(error: string) => void> = vi.fn();

const renderUseRegisterForm = (props: IUseRegisterFormProps = {}) => {
  return renderHook(() =>
    useRegisterForm({
      onSuccess: mockOnSuccess,
      onError: mockOnError,
      ...props,
    }),
  );
};

describe("useRegisterForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useNavigate).mockReturnValue(mockNavigate);
    vi.mocked(useRegisterMutation).mockReturnValue([
      mockRegister,
      { isLoading: false, reset: vi.fn() },
    ]);

    mockValidateRegistrationForm.mockReturnValue(mockValidValidationResults);
    mockIsFormValid.mockReturnValue(true);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  // Mocked functions available via vi.mocked()
  const mockValidateRegistrationForm = vi.mocked(validateRegistrationForm);
  const mockIsFormValid = vi.mocked(isFormValid);
  const mockParseDjangoApiErrors = vi.mocked(parseDjangoApiErrors);
  const mockHasFieldErrors = vi.mocked(hasFieldErrors);

  const mockValidValidationResults: Record<string, IValidationResult> = {
    username: { isValid: true },
    email: { isValid: true },
    password: { isValid: true },
    passwordConfirm: { isValid: true },
    firstName: { isValid: true },
    lastName: { isValid: true },
  };

  /**
   * @description Should initialize with correct initial state
   * @scenario Render hook with default props
   * @expected formData empty strings, empty errors/touched, false submitting
   */
  it("should initialize correctly", () => {
    const { result } = renderUseRegisterForm();

    const expectedFormData: IRegisterFormValues = {
      username: "",
      email: "",
      password: "",
      passwordConfirm: "",
      firstName: "",
      lastName: "",
    };
    const expectedTouched: IRegisterFormTouched = {
      username: false,
      email: false,
      password: false,
      passwordConfirm: false,
      firstName: false,
      lastName: false,
    };
    const expectedErrors: IRegisterFormErrors = {};

    expect(result.current.formData).toEqual(expectedFormData);
    expect(result.current.touched).toEqual(expectedTouched);
    expect(result.current.errors).toEqual(expectedErrors);
    expect(result.current.isSubmitting).toBe(false);
  });

  /**
   * @description Should provide correct handler functions
   * @scenario Initial render provides all expected methods
   * @expected All handlers exist and are functions
   */
  it("should provide all expected handlers", () => {
    const { result } = renderUseRegisterForm();

    expect(typeof result.current.handleChange).toBe("function");
    expect(typeof result.current.handleBlur).toBe("function");
    expect(typeof result.current.handleSubmit).toBe("function");
    expect(typeof result.current.resetForm).toBe("function");
  });

  describe("handleChange", () => {
    /**
     * @description Should update specific field value
     * @scenario Change username field
     * @expected Only username updated
     */
    it("should update field value", () => {
      const { result } = renderUseRegisterForm();

      act(() => {
        result.current.handleChange("username")("testuser");
      });

      expect(result.current.formData.username).toBe("testuser");
      expect(result.current.formData.email).toBe("");
    });

    /**
     * @description Should clear existing field error on change
     * @scenario Pre-set error, then change field
     * @expected Field error cleared
     */
    it("should clear field error on change", () => {
      const { result } = renderUseRegisterForm();

      act(() => {
        result.current.handleChange("username")("test");
        mockValidateRegistrationForm.mockReturnValueOnce({
          username: { isValid: false, error: "Error" },
          email: { isValid: true },
          password: { isValid: true },
          passwordConfirm: { isValid: true },
          firstName: { isValid: true },
          lastName: { isValid: true },
        });
        result.current.handleBlur("username")();
      });

      act(() => {
        result.current.handleChange("username")("newtest");
      });

      expect(result.current.errors.username).toBeUndefined();
    });
  });

  describe("handleBlur", () => {
    /**
     * @description Should mark field as touched on blur
     * @scenario Blur username field
     * @expected touched.username true
     */
    it("should mark field as touched", () => {
      const { result } = renderUseRegisterForm();

      act(() => {
        result.current.handleBlur("username")();
      });

      expect(result.current.touched.username).toBe(true);
    });

    /**
     * @description Should trigger full validation on blur
     * @scenario Blur field calls validateRegistrationForm with formData
     * @expected Validator called with current formData
     */
    it("should trigger full form validation on blur", () => {
      const { result } = renderUseRegisterForm();

      act(() => {
        result.current.handleBlur("email")();
      });

      expect(mockValidateRegistrationForm).toHaveBeenCalled();
    });

    /**
     * @description Should set error for touched invalid field
     * @scenario Blur invalid username
     * @expected username error set
     */
    it("should set error for touched invalid field", () => {
      mockValidateRegistrationForm.mockReturnValue({
        username: { isValid: false, error: "Invalid" },
        email: { isValid: true },
        password: { isValid: true },
        passwordConfirm: { isValid: true },
        firstName: { isValid: true },
        lastName: { isValid: true },
      });

      const { result } = renderUseRegisterForm();

      act(() => {
        result.current.handleBlur("username")();
      });

      expect(result.current.errors.username).toBe("Invalid");
    });
  });

  describe("handleSubmit", () => {
    /**
     * @description Should not submit invalid form
     * @scenario Invalid data on submit
     * @expected No register call, errors set, all touched
     */
    it("should not submit invalid form", async () => {
      mockValidateRegistrationForm.mockReturnValue({
        username: { isValid: false, error: "Invalid" },
        email: { isValid: false, error: "Invalid" },
        password: { isValid: false, error: "Invalid" },
        passwordConfirm: { isValid: false, error: "Invalid" },
        firstName: { isValid: false, error: "Invalid" },
        lastName: { isValid: false, error: "Invalid" },
      });
      mockIsFormValid.mockReturnValue(false);

      const { result } = renderUseRegisterForm();

      const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
      await act(async () => {
        await result.current.handleSubmit(
          mockEvent as React.FormEvent<HTMLFormElement>,
        );
      });

      expect(vi.mocked(mockRegister)).not.toHaveBeenCalled();
      expect(result.current.touched.username).toBe(true);
      expect(result.current.touched.email).toBe(true);
    });

    /**
     * @description Should handle successful registration
     * @scenario Valid form + successful API
     * @expected register called, onSuccess, navigate
     */
    it("should handle successful submission", async () => {
      const { result } = renderUseRegisterForm({
        onSuccess: mockOnSuccess,
        onError: mockOnError,
      });

      // Fill form with valid data to pass validation
      act(() => {
        result.current.handleChange("username")("testuser");
        result.current.handleChange("email")("test@example.com");
        result.current.handleChange("password")("Password123");
        result.current.handleChange("passwordConfirm")("Password123");
        result.current.handleChange("firstName")("Test");
        result.current.handleChange("lastName")("User");
      });

      mockRegister.mockReturnValue({
        unwrap: () =>
          Promise.resolve({ user: { id: 1 }, access: "mock_token" }),
      });

      const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
      await act(async () => {
        await result.current.handleSubmit(
          mockEvent as React.FormEvent<HTMLFormElement>,
        );
      });

      expect(mockRegister).toHaveBeenCalled();
      expect(mockOnSuccess).toHaveBeenCalled();
      expect(mockNavigate).toHaveBeenCalledWith("/disk", { replace: true });
    });

    describe("when API returns an error", () => {
      beforeEach(() => {
        // Fill valid form data to pass validation
        const { result } = renderUseRegisterForm();
        act(() => {
          result.current.handleChange("username")("testuser");
          result.current.handleChange("email")("test@example.com");
          result.current.handleChange("password")("Password123");
          result.current.handleChange("passwordConfirm")("Password123");
          result.current.handleChange("firstName")("Test");
          result.current.handleChange("lastName")("User");
        });
      });

      /**
       * @description Should handle field errors from API
       * @scenario API returns field-specific errors (e.g., username taken)
       * @expected Errors set, onError called with first field error message
       */
      it("should set field errors when API returns fieldErrors", async () => {
        // Arrange
        const apiError = {
          data: {
            username: ["User with this username already exists."],
            email: ["Email is invalid."],
          },
        };
        const parsedFieldErrors: Record<string, string> = {
          username: "User with this username already exists.",
          email: "Email is invalid.",
        };
        mockParseDjangoApiErrors.mockReturnValue({
          fieldErrors: parsedFieldErrors,
          submitError: undefined,
        });
        mockHasFieldErrors.mockReturnValue(true);

        mockRegister.mockReturnValue({
          unwrap: () => Promise.reject(apiError),
        });

        const { result } = renderUseRegisterForm({
          onSuccess: mockOnSuccess,
          onError: mockOnError,
        });

        // Re-fill form in this specific render
        act(() => {
          result.current.handleChange("username")("testuser");
          result.current.handleChange("email")("test@example.com");
          result.current.handleChange("password")("Password123");
          result.current.handleChange("passwordConfirm")("Password123");
          result.current.handleChange("firstName")("Test");
          result.current.handleChange("lastName")("User");
        });

        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };

        // Act
        await act(async () => {
          await result.current.handleSubmit(
            mockEvent as React.FormEvent<HTMLFormElement>,
          );
        });

        // Assert
        expect(mockRegister).toHaveBeenCalled();
        expect(mockParseDjangoApiErrors).toHaveBeenCalledWith(apiError.data);
        expect(result.current.errors.username).toBe(
          "User with this username already exists.",
        );
        expect(result.current.errors.email).toBe("Email is invalid.");
        expect(result.current.errors.submit).toBeUndefined();
        expect(mockOnError).toHaveBeenCalledWith(
          "User with this username already exists.",
        );
        expect(mockOnSuccess).not.toHaveBeenCalled();
        expect(mockNavigate).not.toHaveBeenCalled();
      });

      /**
       * @description Should handle submitError from API
       * @scenario API returns a non-field-specific error
       * @expected submit error set, onError called with submitError
       */
      it("should set submit error when API returns submitError", async () => {
        // Arrange
        const apiError = {
          data: { non_field_errors: ["Registration disabled"] },
        };
        const parsedSubmitError = "Registration disabled";
        mockParseDjangoApiErrors.mockReturnValue({
          fieldErrors: {},
          submitError: parsedSubmitError,
        });
        mockHasFieldErrors.mockReturnValue(false);

        mockRegister.mockReturnValue({
          unwrap: () => Promise.reject(apiError),
        });

        const { result } = renderUseRegisterForm({
          onSuccess: mockOnSuccess,
          onError: mockOnError,
        });

        act(() => {
          result.current.handleChange("username")("testuser");
          result.current.handleChange("email")("test@example.com");
          result.current.handleChange("password")("Password123");
          result.current.handleChange("passwordConfirm")("Password123");
          result.current.handleChange("firstName")("Test");
          result.current.handleChange("lastName")("User");
        });

        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };

        // Act
        await act(async () => {
          await result.current.handleSubmit(
            mockEvent as React.FormEvent<HTMLFormElement>,
          );
        });

        // Assert
        expect(result.current.errors.submit).toBe(parsedSubmitError);
        expect(mockOnError).toHaveBeenCalledWith(parsedSubmitError);
      });

      /**
       * @description Should set generic error when API error has neither fieldErrors nor submitError
       * @scenario API error object has no recognizable error data
       * @expected Generic submit error set, onError called with generic message
       */
      it("should set generic submit error when no fieldErrors and no submitError", async () => {
        // Arrange
        const apiError = { data: { some_weird_structure: [] } };
        mockParseDjangoApiErrors.mockReturnValue({
          fieldErrors: {},
          submitError: undefined,
        });
        mockHasFieldErrors.mockReturnValue(false);

        mockRegister.mockReturnValue({
          unwrap: () => Promise.reject(apiError),
        });

        const { result } = renderUseRegisterForm({
          onSuccess: mockOnSuccess,
          onError: mockOnError,
        });

        act(() => {
          result.current.handleChange("username")("testuser");
          result.current.handleChange("email")("test@example.com");
          result.current.handleChange("password")("Password123");
          result.current.handleChange("passwordConfirm")("Password123");
          result.current.handleChange("firstName")("Test");
          result.current.handleChange("lastName")("User");
        });

        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };

        // Act
        await act(async () => {
          await result.current.handleSubmit(
            mockEvent as React.FormEvent<HTMLFormElement>,
          );
        });

        // Assert
        expect(result.current.errors.submit).toBe(
          "Ошибка регистрации. Попробуйте позже.",
        );
        expect(mockOnError).toHaveBeenCalledWith(
          "Ошибка регистрации. Попробуйте позже.",
        );
      });

      /**
       * @description Should handle error without 'data' property
       * @scenario Rejected value is not an object or has no 'data' field
       * @expected Generic error set, onError called with generic message
       */
      it("should handle error without data property", async () => {
        // Arrange
        const apiError = "Network failure"; // string, not an object
        mockRegister.mockReturnValue({
          unwrap: () => Promise.reject(apiError),
        });

        const { result } = renderUseRegisterForm({
          onSuccess: mockOnSuccess,
          onError: mockOnError,
        });

        act(() => {
          result.current.handleChange("username")("testuser");
          result.current.handleChange("email")("test@example.com");
          result.current.handleChange("password")("Password123");
          result.current.handleChange("passwordConfirm")("Password123");
          result.current.handleChange("firstName")("Test");
          result.current.handleChange("lastName")("User");
        });

        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };

        // Act
        await act(async () => {
          await result.current.handleSubmit(
            mockEvent as React.FormEvent<HTMLFormElement>,
          );
        });

        // Assert
        expect(mockParseDjangoApiErrors).not.toHaveBeenCalled(); // because condition `'data' in error` fails
        expect(result.current.errors.submit).toBe(
          "Ошибка регистрации. Попробуйте позже.",
        );
        expect(mockOnError).toHaveBeenCalledWith(
          "Ошибка регистрации. Попробуйте позже.",
        );
      });

      /**
       * @description Should preserve existing errors and merge new ones
       * @scenario Existing error on username, API returns email error
       * @expected Both errors present, submit error not overwritten if not provided
       */
      it("should merge new API errors with existing errors", async () => {
        // Arrange
        const { result } = renderUseRegisterForm({
          onSuccess: mockOnSuccess,
          onError: mockOnError,
        });

        // Set an existing error manually
        act(() => {
          result.current.handleChange("username")("existing");
          mockValidateRegistrationForm.mockReturnValueOnce({
            username: { isValid: false, error: "Previous username error" },
            email: { isValid: true },
            password: { isValid: true },
            passwordConfirm: { isValid: true },
            firstName: { isValid: true },
            lastName: { isValid: true },
          });
          result.current.handleBlur("username")();
        });
        expect(result.current.errors.username).toBe("Previous username error");

        // Fill valid data for other fields
        act(() => {
          result.current.handleChange("email")("test@example.com");
          result.current.handleChange("password")("Password123");
          result.current.handleChange("passwordConfirm")("Password123");
          result.current.handleChange("firstName")("Test");
          result.current.handleChange("lastName")("User");
        });

        const apiError = { data: { email: ["Email already taken."] } };
        mockParseDjangoApiErrors.mockReturnValue({
          fieldErrors: { email: "Email already taken." },
          submitError: undefined,
        });
        mockHasFieldErrors.mockReturnValue(true);

        mockRegister.mockReturnValue({
          unwrap: () => Promise.reject(apiError),
        });

        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };

        // Act
        await act(async () => {
          await result.current.handleSubmit(
            mockEvent as React.FormEvent<HTMLFormElement>,
          );
        });

        // Assert
        expect(result.current.errors.username).toBe("Previous username error");
        expect(result.current.errors.email).toBe("Email already taken.");
        expect(result.current.errors.submit).toBeUndefined();
      });
    });
  });

  describe("resetForm", () => {
    /**
     * @description Should reset all state to initial
     * @scenario Modify state, then reset
     * @expected All state initial
     */
    it("should reset all state to initial", () => {
      const { result } = renderUseRegisterForm();

      act(() => {
        result.current.handleChange("username")("test");
      });

      act(() => {
        result.current.resetForm();
      });

      expect(result.current.formData.username).toBe("");
      expect(result.current.errors).toEqual({});
      expect(result.current.touched.username).toBe(false);
    });
  });

  describe("isSubmitting", () => {
    /**
     * @description Should reflect RTK isLoading state
     * @scenario Mock isLoading true/false
     * @expected isSubmitting matches
     */
    it.each([
      [false, false],
      [true, true],
    ])("should reflect RTK isLoading %s", (isLoading, expected) => {
      vi.mocked(useRegisterMutation).mockReturnValue([
        mockRegister,
        { isLoading, reset: vi.fn() },
      ]);

      const { result } = renderUseRegisterForm();
      expect(result.current.isSubmitting).toBe(expected);
    });
  });
});
