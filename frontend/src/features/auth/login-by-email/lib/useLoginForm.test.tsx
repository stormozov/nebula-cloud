import { configureStore } from "@reduxjs/toolkit";
import { act, renderHook } from "@testing-library/react";
import { Provider } from "react-redux";
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

import { useLoginMutation } from "@/entities/user";
import userReducer from "@/entities/user/model/slice";
import { hasFieldErrors, parseDjangoApiErrors } from "@/shared/api";
import { validateLogin, validatePassword } from "@/shared/validators";

import type { IMockFormEvent } from "./test-helpers";
import type { IUseLoginFormProps } from "./types";
import { useLoginForm } from "./useLoginForm";

// Mock all dependencies
vi.mock("react-router", () => ({
  useNavigate: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  useLoginMutation: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  parseDjangoApiErrors: vi.fn(),
  hasFieldErrors: vi.fn(),
}));

vi.mock("@/shared/validators", () => ({
  validateLogin: vi.fn(),
  validatePassword: vi.fn(),
}));

const mockNavigate: Mock = vi.fn();
const mockLogin: Mock = vi.fn();
const mockOnSuccess: Mock = vi.fn();
const mockOnError: Mock<(error: string) => void> = vi.fn();

const renderUseLoginForm = (props: IUseLoginFormProps = {}) => {
  const store = configureStore({
    reducer: {
      user: userReducer,
    },
  });

  return renderHook(
    () =>
      useLoginForm({
        onSuccess: mockOnSuccess,
        onError: mockOnError,
        ...props,
      }),
    {
      wrapper: ({ children }) => <Provider store={store}>{children}</Provider>,
    },
  );
};

describe("useLoginForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const mockUseNavigate = useNavigate as unknown as Mock<
      () => ReturnType<typeof useNavigate>
    >;
    mockUseNavigate.mockReturnValue(mockNavigate);
    vi.mocked(useLoginMutation).mockReturnValue([
      mockLogin,
      { isLoading: false, reset: vi.fn() },
    ]);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("Hook Initialization", () => {
    /**
     * @description Should initialize formData with empty strings
     * @scenario Render hook without props
     * @expected formData.username and formData.password are empty strings
     */
    it("should initialize formData correctly", () => {
      const { result } = renderUseLoginForm();

      expect(result.current.formData).toEqual({
        username: "",
        password: "",
      });
    });

    /**
     * @description Should initialize errors as empty object
     * @scenario Render hook without props
     * @expected errors object is empty, isSubmitting is false
     */
    it("should initialize errors and isSubmitting correctly", () => {
      const { result } = renderUseLoginForm();

      expect(result.current.errors).toEqual({});
      expect(result.current.isSubmitting).toBe(false);
    });
  });

  describe("Form Field Changes", () => {
    /**
     * @description Should update username on change
     * @scenario Call handleChange('username') with value
     * @expected formData.username updated, error cleared if existed
     */
    it("should update username field on change", async () => {
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("testuser");
      });

      expect(result.current.formData.username).toBe("testuser");
    });

    /**
     * @description Should update password on change
     * @scenario Call handleChange('password') with value
     * @expected formData.password updated
     */
    it("should update password field on change", async () => {
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("password")("pass123");
      });

      expect(result.current.formData.password).toBe("pass123");
    });

    /**
     * @description Should clear field error on change
     * @scenario Set error first, then change field
     * @expected Error for that field becomes undefined
     */
    it("should clear field error on change", async () => {
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("weak");
        result.current.handleBlur("username")();
      });

      act(() => {
        result.current.handleChange("username")("testuser");
      });

      expect(result.current.errors.username).toBeUndefined();
    });

    /**
     * @description Should preserve other field errors on single field change
     * @scenario Error on password, change username
     * @expected username error cleared, password error remains (setup)
     */
    it("should preserve other field errors when changing one field", async () => {
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValueOnce({
        isValid: false,
        error: "error",
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("password")("weak");
        result.current.handleBlur("password")();
        result.current.handleChange("username")("testuser");
      });

      expect(result.current.formData.username).toBe("testuser");
      expect(result.current.errors.password).toBe("error");
    });
  });

  describe("Field Blur Validation", () => {
    beforeEach(() => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
    });

    /**
     * @description Should validate username on blur when valid
     * @scenario Set valid username, blur
     * @expected No error set
     */
    it("should not set error for valid username on blur", async () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("validuser");
      });
      act(() => {
        result.current.handleBlur("username")();
      });

      expect(result.current.errors.username).toBeUndefined();
      expect(validateLogin).toHaveBeenCalledWith("validuser");
    });

    /**
     * @description Should set error for invalid username on blur
     * @scenario Set invalid username, blur
     * @expected username error set from validator
     */
    it("should set error for invalid username on blur", async () => {
      const mockError = { isValid: false, error: "Invalid username" };
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue(mockError);
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("invalid");
      });
      act(() => {
        result.current.handleBlur("username")();
      });

      expect(result.current.errors.username).toBe("Invalid username");
      expect(validateLogin).toHaveBeenCalledWith("invalid");
    });

    /**
     * @description Should validate password on blur when valid
     * @scenario Set valid password, blur
     * @expected No error set
     */
    it("should not set error for valid password on blur", async () => {
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("password")("ValidPass1!");
        result.current.handleBlur("password")();
      });

      expect(result.current.errors.password).toBeUndefined();
    });

    /**
     * @description Should set error for invalid password on blur
     * @scenario Set invalid password, blur
     * @expected password error set
     */
    it("should set error for invalid password on blur", async () => {
      const mockError = { isValid: false, error: "Invalid password" };
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue(mockError);
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("password")("weak");
      });
      act(() => {
        result.current.handleBlur("password")();
      });

      expect(result.current.errors.password).toBe("Invalid password");
      expect(validatePassword).toHaveBeenCalledWith("weak");
    });
  });

  describe("Form Reset", () => {
    /**
     * @description Should reset formData to initial state
     * @scenario Fill form, then reset
     * @expected formData back to empty
     */
    it("should reset formData to initial state", async () => {
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("test");
        result.current.handleChange("password")("pass");
      });

      act(() => {
        result.current.resetForm();
      });

      expect(result.current.formData).toEqual({
        username: "",
        password: "",
      });
    });

    /**
     * @description Should reset all errors
     * @scenario Set errors, then reset
     * @expected errors empty object
     */
    it("should reset all errors", async () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValueOnce({
        isValid: false,
        error: "err",
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValueOnce({
        isValid: false,
        error: "err",
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("weak");
        result.current.handleBlur("username")();
        result.current.handleChange("password")("weak");
        result.current.handleBlur("password")();
      });

      act(() => {
        result.current.resetForm();
      });

      expect(result.current.errors).toEqual({});
    });
  });

  describe("Form Submission - Client Validation", () => {
    /**
     * @description Should submit when all fields valid
     * @scenario Valid form data, submit
     * @expected No client errors, mutation called
     */
    it("should proceed to API call when client validation passes", () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      mockLogin.mockResolvedValue({ unwrap: vi.fn().mockResolvedValue({}) });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("user");
        result.current.handleChange("password")("pass123!");
      });

      act(() => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(mockLogin).toHaveBeenCalledWith({
        username: "user",
        password: "pass123!",
      });
    });

    /**
     * @description Should set username error if invalid on submit
     * @scenario Invalid username, valid password on submit
     * @expected username error set, no API call
     */
    it("should set username error and not submit if username invalid", () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: false,
        error: "Invalid login",
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("bad");
        result.current.handleChange("password")("good");
      });

      act(() => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(result.current.errors.username).toBe("Invalid login");
      expect(mockLogin).not.toHaveBeenCalled();
    });

    /**
     * @description Should set password error if invalid on submit
     * @scenario Valid username, invalid password
     * @expected password error set, no submit
     */
    it("should set password error and not submit if password invalid", () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: false,
        error: "Invalid password",
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("good");
        result.current.handleChange("password")("bad");
      });

      act(() => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(result.current.errors.password).toBe("Invalid password");
      expect(mockLogin).not.toHaveBeenCalled();
    });

    /**
     * @description Should set both errors if both invalid
     * @scenario Both fields invalid on submit
     * @expected Both errors set
     */
    it("should set both field errors if both invalid", () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: false,
        error: "Bad login",
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: false,
        error: "Bad password",
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("bad1");
        result.current.handleChange("password")("bad2");
      });

      act(() => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(result.current.errors).toEqual({
        username: "Bad login",
        password: "Bad password",
      });
    });

    /**
     * @description Should call preventDefault on submit
     * @scenario Any submit call
     * @expected preventDefault called on event
     */
    it("should call preventDefault on submit", () => {
      const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(mockEvent.preventDefault).toHaveBeenCalled();
    });
  });

  describe("Form Submission - Success", () => {
    /**
     * @description Should call onSuccess and navigate on API success
     * @scenario Valid form, mutation succeeds
     * @expected onSuccess and navigate('/disk') called
     */
    it("should call onSuccess and navigate on successful login", async () => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      mockLogin.mockReturnValue({
        unwrap: vi
          .fn()
          .mockResolvedValue({ access: "mock-token", refresh: "mock-refresh" }),
      });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("user");
        result.current.handleChange("password")("pass");
      });

      await act(async () => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(mockOnSuccess).toHaveBeenCalled();
      expect(mockNavigate).toHaveBeenCalledWith("/disk", { replace: true });
    });
  });

  describe("Form Submission - API Errors", () => {
    beforeEach(() => {
      (validateLogin as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
      (validatePassword as ReturnType<typeof vi.fn>).mockReturnValue({
        isValid: true,
      });
    });

    /**
     * @description Should handle 500 server error
     * @scenario Mutation rejects with 500 status
     * @expected submit error set to hardcoded message
     */
    it("should handle 500 server error with hardcoded message", async () => {
      mockLogin.mockRejectedValue({ status: 500 });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("user");
        result.current.handleChange("password")("pass");
      });

      await act(async () => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(result.current.errors.submit).toBe(
        "Ошибка входа. Проверьте логин и пароль.",
      );
    });

    /**
     * @description Should handle API field errors via parseDjangoApiErrors
     * @scenario API returns field errors, hasFieldErrors true
     * @expected Field errors set, onError called
     */
    it("should handle API field errors from parsed data", async () => {
      const mockParsed = {
        fieldErrors: { username: "User exists" },
        submitError: undefined,
      };
      (parseDjangoApiErrors as ReturnType<typeof vi.fn>).mockReturnValue(
        mockParsed,
      );
      (hasFieldErrors as ReturnType<typeof vi.fn>).mockReturnValue(true);
      const mockUnwrap = vi.fn().mockRejectedValue({
        status: 400,
        data: { username: ["User exists"] },
      });
      mockLogin.mockReturnValue({ unwrap: mockUnwrap });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("user");
        result.current.handleChange("password")("pass");
      });

      await act(async () => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(parseDjangoApiErrors).toHaveBeenCalled();
      expect(hasFieldErrors).toHaveBeenCalledWith(mockParsed.fieldErrors);
      expect(result.current.errors.username).toBe("User exists");
      expect(mockOnError).toHaveBeenCalledWith("User exists");
    });

    /**
     * @description Should handle API detail/submit error
     * @scenario API returns {detail: 'Invalid creds'}
     * @expected submit error set from parsed.submitError
     */
    it("should handle API detail error as submit error", async () => {
      const mockParsed = {
        fieldErrors: {},
        submitError: "Invalid credentials",
      };
      (parseDjangoApiErrors as ReturnType<typeof vi.fn>).mockReturnValue(
        mockParsed,
      );
      (hasFieldErrors as ReturnType<typeof vi.fn>).mockReturnValue(false);
      mockLogin.mockRejectedValue({ data: { detail: "Invalid credentials" } });
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("user");
        result.current.handleChange("password")("pass");
      });

      await act(async () => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(result.current.errors.submit).toBe(
        "Ошибка входа. Проверьте логин и пароль.",
      );
      expect(mockOnError).toHaveBeenCalledWith(
        "Ошибка входа. Проверьте логин и пароль.",
      );
    });

    /**
     * @description Should use fallback error if no specific handling
     * @scenario Unknown error shape
     * @expected Fallback 'Ошибка входа...' in submit
     */
    it("should use fallback error for unknown error", () => {
      mockLogin.mockRejectedValue(new Error("Unknown"));
      const { result } = renderUseLoginForm();

      act(() => {
        result.current.handleChange("username")("user");
        result.current.handleChange("password")("pass");
      });

      act(() => {
        const mockEvent: IMockFormEvent = { preventDefault: vi.fn() };
        result.current.handleSubmit(mockEvent as unknown as React.FormEvent);
      });

      expect(result.current.errors.submit).toBe(
        "Ошибка входа. Проверьте логин и пароль.",
      );
    });

    /**
     * @description isSubmitting should be false when mutation is not loading
     * @scenario Render hook with isLoading: false
     * @expected isSubmitting is false
     */
    it("should have isSubmitting false when mutation is not loading", () => {
      vi.mocked(useLoginMutation).mockReturnValue([
        mockLogin,
        { isLoading: false, reset: vi.fn() },
      ]);

      const { result } = renderUseLoginForm();

      expect(result.current.isSubmitting).toBe(false);
    });

    /**
     * @description isSubmitting should be true when mutation is loading
     * @scenario Render hook with isLoading: true
     * @expected isSubmitting is true
     */
    it("should have isSubmitting true when mutation is loading", () => {
      (useLoginMutation as unknown as Mock).mockReturnValue([
        mockLogin,
        { isLoading: true, reset: vi.fn() },
      ]);

      const { result } = renderUseLoginForm();

      expect(result.current.isSubmitting).toBe(true);
    });
  });
});
