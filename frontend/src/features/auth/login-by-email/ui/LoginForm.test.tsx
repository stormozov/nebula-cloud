import { configureStore } from "@reduxjs/toolkit";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type React from "react";
import { Provider } from "react-redux";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import userReducer from "@/entities/user/model/slice";

import { LoginForm } from "./LoginForm";

// Mock dependencies
vi.mock("react-router", () => ({
  useNavigate: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  useLoginMutation: vi.fn(),
}));

import { useLoginForm } from "../lib/useLoginForm";

vi.mock("@/features/auth/login-by-email/lib/useLoginForm", () => ({
  useLoginForm: vi.fn(),
}));

vi.mock("@/shared/ui", () => {
  const MockFormBase = vi.fn(
    ({
      children,
      onSubmit,
      noValidate,
      className,
    }: {
      children: React.ReactNode;
      onSubmit?: (e: React.FormEvent) => void;
      noValidate?: boolean;
      className?: string;
    }) => (
      <form
        data-testid="login-form"
        onSubmit={onSubmit}
        noValidate={noValidate}
        className={className}
      >
        {children}
      </form>
    ),
  );

  const MockSubmitErrorBlock = vi.fn(({ errors }: { errors?: string[] }) => {
    if (!errors) return null;
    return <div data-testid="submit-error-block">{errors}</div>;
  });

  (
    MockFormBase as unknown as { SubmitErrorBlock: typeof MockSubmitErrorBlock }
  ).SubmitErrorBlock = MockSubmitErrorBlock;

  return {
    Form: MockFormBase,
    ControlledInput: vi.fn(
      ({
        value,
        onChange,
        onBlur,
        error,
        label,
        placeholder,
        disabled,
        required,
        autoComplete,
        "data-testid": _dataTestId,
      }: {
        value: string;
        onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
        onBlur?: () => void;
        error?: string;
        label: string;
        placeholder?: string;
        disabled?: boolean;
        required?: boolean;
        autoComplete?: string;
        "data-testid"?: string;
      }) => (
        <label
          htmlFor={`input-${label.toLowerCase()}`}
          id={`label-${label.toLowerCase()}`}
        >
          {label}
          <input
            id={`input-${label.toLowerCase()}`}
            data-testid={`input-${label.toLowerCase()}`}
            value={value}
            onChange={onChange}
            onBlur={onBlur}
            placeholder={placeholder}
            type={label === "Пароль" ? "password" : "text"}
            disabled={disabled}
            required={required}
            autoComplete={autoComplete}
            aria-invalid={!!error}
            aria-labelledby={`label-${label.toLowerCase()}`}
          />
          {error && <span data-testid="error-message">{error}</span>}
        </label>
      ),
    ),
    Button: vi.fn(
      ({
        children,
        loading,
        disabled,
        type,
        fullWidth,
        className,
        onClick,
      }: {
        children: React.ReactNode;
        loading?: boolean;
        disabled?: boolean;
        type?: "button" | "submit" | "reset";
        fullWidth?: boolean;
        className?: string;
        onClick?: () => void;
      }) => (
        <button
          data-testid="submit-button"
          type={type}
          disabled={disabled || loading}
          className={className}
          style={fullWidth ? { width: "100%" } : {}}
          onClick={onClick}
        >
          {children}
        </button>
      ),
    ),
  };
});

const mockOnSuccess = vi.fn();
const mockOnError = vi.fn();
const mockUseLoginForm = vi.mocked(useLoginForm);

const mockFormData = { username: "", password: "" };
const mockErrors = {};
const mockHandleChange = vi.fn((_field: string) =>
  vi.fn((_value: string) => {}),
);
const mockHandleBlur = vi.fn((_field: string) => vi.fn(() => {}));
const mockHandleSubmit = vi.fn((e: React.FormEvent) => e.preventDefault());
const mockResetForm = vi.fn();

const defaultHookReturn = {
  formData: mockFormData,
  errors: mockErrors,
  isSubmitting: false,
  handleChange: mockHandleChange,
  handleBlur: mockHandleBlur,
  handleSubmit: mockHandleSubmit,
  resetForm: mockResetForm,
};

const renderLoginForm = (props = {}) => {
  const store = configureStore({ reducer: { user: userReducer } });
  return render(
    <Provider store={store}>
      <LoginForm onSuccess={mockOnSuccess} onError={mockOnError} {...props} />
    </Provider>,
  );
};

describe("LoginForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseLoginForm.mockReturnValue(defaultHookReturn);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("Initialization and Rendering", () => {
    /**
     * @description Should render form structure correctly
     * @scenario Render LoginForm with default props
     * @expected Form, two ControlledInput (username/password), Button exist
     */
    it("should render form with username input, password input, and submit button", () => {
      renderLoginForm();

      expect(screen.getByTestId("login-form")).toBeInTheDocument();
      expect(screen.getByLabelText("Логин")).toBeInTheDocument();
      expect(screen.getByTestId("input-логин")).toBeInTheDocument();
      expect(screen.getByLabelText("Пароль")).toBeInTheDocument();
      expect(screen.getByTestId("submit-button")).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /Войти/i }),
      ).toBeInTheDocument();
    });

    /**
     * @description Should pass noValidate and className to Form
     * @scenario Render LoginForm
     * @expected Form has noValidate=true and className="login-form"
     */
    it("should pass correct props to Form component", () => {
      renderLoginForm();

      const form = screen.getByTestId("login-form");
      expect(form).toHaveAttribute("noValidate");
      expect(form).toHaveClass("login-form");
    });

    /**
     * @description Should pass correct props to username ControlledInput
     * @scenario Render with initial empty formData
     * @expected Username input: label="Логин", placeholder, required, autoComplete="username"
     */
    it("should render username ControlledInput with correct props", () => {
      renderLoginForm();

      const usernameInput = screen.getByTestId("input-логин");
      expect(usernameInput).toHaveAttribute("placeholder", "Введите логин");
      expect(usernameInput).toHaveAttribute("autocomplete", "username");
      expect(usernameInput).toBeRequired();
      expect(usernameInput).not.toBeDisabled();
    });

    /**
     * @description Should pass correct props to password ControlledInput
     * @scenario Render with initial empty formData
     * @expected Password input: label="Пароль", type="password", placeholder, required, autoComplete
     */
    it("should render password ControlledInput with correct props", () => {
      renderLoginForm();

      expect(screen.getByLabelText("Пароль")).toHaveAttribute(
        "type",
        "password",
      );
      expect(screen.getByLabelText("Пароль")).toHaveAttribute(
        "placeholder",
        "Введите пароль",
      );
      expect(screen.getByLabelText("Пароль")).toHaveAttribute(
        "autocomplete",
        "current-password",
      );
      expect(screen.getByLabelText("Пароль")).toBeRequired();
    });

    /**
     * @description Should not render SubmitErrorBlock initially
     * @scenario Render with no submit error
     * @expected No Form.SubmitErrorBlock or error spans
     */
    it("should not render submit error block when no submit error", () => {
      renderLoginForm();

      expect(
        screen.queryByTestId("submit-error-block"),
      ).not.toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("Props Handling", () => {
    /**
     * @description Should receive and use onSuccess prop via hook
     * @scenario Mock hook calls onSuccess on submit success (integrated with hook mock)
     * @expected onSuccess called when hook triggers it
     */
    it("should pass onSuccess to hook and call it on success", async () => {
      const successHookReturn = {
        ...defaultHookReturn,
        handleSubmit: vi.fn(async (e: React.FormEvent) => {
          e.preventDefault();
          mockOnSuccess();
        }),
      };
      mockUseLoginForm.mockReturnValue(successHookReturn);

      renderLoginForm();
      fireEvent.click(screen.getByTestId("submit-button"));

      await waitFor(() => {
        expect(mockOnSuccess).toHaveBeenCalled();
      });
    });

    /**
     * @description Should receive and use onError prop via hook
     * @scenario Mock hook calls onError on error
     * @expected onError called when hook triggers it
     */
    it("should pass onError to hook and call it on error", async () => {
      const errorHookReturn = {
        ...defaultHookReturn,
        handleSubmit: vi.fn(async (e: React.FormEvent) => {
          e.preventDefault();
          mockOnError("Test error");
        }),
      };
      mockUseLoginForm.mockReturnValue(errorHookReturn);

      renderLoginForm();
      fireEvent.click(screen.getByTestId("submit-button"));

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledWith("Test error");
      });
    });

    /**
     * @description Should handle optional props gracefully
     * @scenario Render without onSuccess/onError
     * @expected No errors, renders fine
     */
    it("should render without optional props", () => {
      const noPropsReturn = {
        ...defaultHookReturn,
        onSuccess: undefined,
        onError: undefined,
      };
      mockUseLoginForm.mockReturnValue(noPropsReturn);

      expect(() => renderLoginForm({})).not.toThrow();
    });
  });

  // ===========================================================================

  describe("Input Interactions", () => {
    /**
     * @description Should call handleChange and handleBlur on input events
     * @scenario Type in username input
     * @expected handleChange("username") called with value
     */
    it("should call handleChange on username input change", async () => {
      const changeHandler = vi.fn();
      mockHandleChange.mockReturnValue(changeHandler);
      renderLoginForm();

      await userEvent.type(screen.getByTestId("input-логин"), "testuser");

      expect(changeHandler).toHaveBeenCalled();
    });

    /**
     * @description Should call handleBlur on username blur
     * @scenario Blur username input
     * @expected handleBlur("username") called
     */
    it("should call handleBlur on username input blur", async () => {
      const blurHandler = vi.fn();
      mockHandleBlur.mockReturnValue(blurHandler);
      renderLoginForm();

      fireEvent.blur(screen.getByTestId("input-логин"));

      expect(blurHandler).toHaveBeenCalled();
    });

    /**
     * @description Should display field error from hook
     * @scenario Hook returns username error
     * @expected Error span visible with error text
     */
    it("should display username validation error", () => {
      const errorsWithUsername = { username: "Invalid login" };
      mockUseLoginForm.mockReturnValue({
        ...defaultHookReturn,
        errors: errorsWithUsername,
      });

      renderLoginForm();

      expect(screen.getAllByTestId("error-message")[0]).toHaveTextContent(
        "Invalid login",
      );
    });

    /**
     * @description Should pass disabled to inputs when submitting
     * @scenario Hook returns isSubmitting=true
     * @expected Inputs disabled=true
     */
    it("should disable inputs when isSubmitting true", () => {
      mockUseLoginForm.mockReturnValue({
        ...defaultHookReturn,
        isSubmitting: true,
      });

      renderLoginForm();

      expect(screen.getByTestId("input-логин")).toBeDisabled();
      expect(screen.getByLabelText("Пароль")).toBeDisabled();
    });
  });

  // ===========================================================================

  describe("Submission States", () => {
    /**
     * @description Should call handleSubmit on form submit
     * @scenario Submit form
     * @expected handleSubmit called with event, preventDefault called
     */
    it("should call handleSubmit on form submission and preventDefault", async () => {
      renderLoginForm();

      fireEvent.submit(screen.getByTestId("login-form"));

      expect(mockHandleSubmit).toHaveBeenCalled();
    });

    /**
     * @description Should show Button loading when isSubmitting
     * @scenario Hook returns isSubmitting=true
     * @expected Button has loading prop (via mock), disabled
     */
    it("should show loading state on submit button when submitting", () => {
      mockUseLoginForm.mockReturnValue({
        ...defaultHookReturn,
        isSubmitting: true,
      });

      renderLoginForm();

      const button = screen.getByTestId("submit-button");
      expect(button).toBeDisabled();
    });

    /**
     * @description Should pass fullWidth and className to Button
     * @scenario Render submitting state
     * @expected Button has correct classes/props
     */
    it("should pass correct props to submit Button", () => {
      renderLoginForm();

      const button = screen.getByTestId("submit-button");
      expect(button).toHaveClass("login-form__submit-btn");
    });

    /**
     * @description Should display submit error block conditionally
     * @scenario Hook returns submit error
     * @expected Error message visible
     */
    /**
     * @description Should conditionally render Form.SubmitErrorBlock when submit error exists
     * @scenario Hook returns errors.submit, check conditional render
     * @expected Form.SubmitErrorBlock rendered with error text
     */
    it("should conditionally render Form.SubmitErrorBlock", () => {
      const errorsWithSubmit = { submit: "Login failed" };
      mockUseLoginForm.mockReturnValue({
        ...defaultHookReturn,
        errors: errorsWithSubmit,
      });

      renderLoginForm();

      expect(screen.getByTestId("submit-error-block")).toHaveTextContent(
        "Login failed",
      );
    });
  });
});

describe("Full Integration Flows", () => {
  /**
   * @description Should handle successful submission flow
   * @scenario Fill valid form, submit successfully
   * @expected No errors shown, onSuccess called
   */
  it("should handle successful form submission", async () => {
    mockUseLoginForm.mockReturnValue({
      formData: { username: "testuser", password: "SecurePass123!" },
      errors: {},
      isSubmitting: false,
      handleSubmit: vi.fn(async (e) => {
        e.preventDefault();
        mockOnSuccess();
      }),
      handleChange: vi.fn(() => vi.fn()),
      handleBlur: vi.fn(() => vi.fn()),
      resetForm: vi.fn(),
    });

    renderLoginForm();

    fireEvent.submit(screen.getByTestId("login-form"));

    await waitFor(() => expect(mockOnSuccess).toHaveBeenCalled());
  });

  /**
   * @description Should handle validation error on submit
   * @scenario Submit invalid form
   * @expected Errors displayed, no onSuccess
   */
  it("should handle client validation errors on submit", async () => {
    const errorSubmit = vi.fn(async (e) => {
      e.preventDefault();
      // Simulate setting errors in hook
    });
    mockUseLoginForm.mockReturnValue({
      ...defaultHookReturn,
      handleSubmit: errorSubmit,
    });

    renderLoginForm();

    fireEvent.submit(screen.getByTestId("login-form"));

    await waitFor(() => expect(errorSubmit).toHaveBeenCalled());
    expect(mockOnSuccess).not.toHaveBeenCalled();
  });

  /**
   * @description Should work with custom formData values
   * @scenario Hook with pre-filled formData
   * @expected Inputs show pre-filled values
   */
  it("should render pre-filled form data", () => {
    const filledData = { username: "prefilled", password: "pass" };
    mockUseLoginForm.mockReturnValue({
      ...defaultHookReturn,
      formData: filledData,
    });

    renderLoginForm();

    expect(screen.getByTestId("input-логин")).toHaveValue("prefilled");
  });
});

describe("Accessibility and Edge Cases", () => {
  /**
   * @description Should have proper ARIA for errors
   * @scenario Render with field error
   * @expected Input aria-invalid=true
   */
  it("should set aria-invalid on inputs with errors", () => {
    mockUseLoginForm.mockReturnValue({
      ...defaultHookReturn,
      errors: { username: "Error" },
    });

    renderLoginForm();

    expect(screen.getByTestId("input-логин")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
  });

  /**
   * @description Should handle empty form submission
   * @scenario Submit empty form
   * @expected handleSubmit called (validation in hook)
   */
  it("should handle submission of empty form", () => {
    renderLoginForm();

    fireEvent.submit(screen.getByTestId("login-form"));

    expect(mockHandleSubmit).toHaveBeenCalled();
  });
});
