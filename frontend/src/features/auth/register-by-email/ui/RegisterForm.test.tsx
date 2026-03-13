import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useRegisterForm } from "../lib/useRegisterForm";
import { RegisterForm } from "./RegisterForm";

/**
 * Mock the useRegisterForm hook to isolate component tests
 */
vi.mock("../lib/useRegisterForm", () => ({
  useRegisterForm: vi.fn(),
}));

/**
 * Mock UI components to focus on RegisterForm logic
 * All mocks defined inside factory to avoid hoisting issues
 */
vi.mock("@/shared/ui", () => {
  /**
   * Mock Button component
   */
  const Button = ({
    children,
    onClick,
    type,
    loading,
    disabled,
    className,
    variant,
    size,
    fullWidth,
  }: {
    children: React.ReactNode;
    onClick?: () => void;
    type?: "submit" | "button";
    loading?: boolean;
    disabled?: boolean;
    className?: string;
    variant?: string;
    size?: string;
    fullWidth?: boolean;
  }) => (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className={className}
      data-testid="submit-button"
      data-loading={loading?.toString()}
      data-variant={variant}
      data-size={size}
      data-full-width={fullWidth?.toString()}
    >
      {children}
    </button>
  );

  /**
   * Mock ControlledInput component
   */
  const ControlledInput = ({
    value,
    onChange,
    onBlur,
    error,
    label,
    placeholder,
    type,
    disabled,
    required,
    autoComplete,
  }: {
    value: string;
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
    onBlur: (e: React.FocusEvent<HTMLInputElement>) => void;
    error?: string;
    label: string;
    placeholder: string;
    type?: string;
    disabled?: boolean;
    required?: boolean;
    autoComplete?: string;
  }) => {
    const inputId = `input-${label.toLowerCase()}`;
    const errorId = `error-${label.toLowerCase()}`;

    return (
      <div className="input-wrapper" data-label={label}>
        <label htmlFor={inputId}>{label}</label>
        <input
          id={inputId}
          value={value}
          onChange={(e) => onChange(e)}
          onBlur={(e) => onBlur(e)}
          placeholder={placeholder}
          type={type || "text"}
          disabled={disabled}
          required={required}
          autoComplete={autoComplete}
          data-testid={inputId}
        />
        {error && (
          <span className="error-message" data-testid={errorId}>
            {error}
          </span>
        )}
      </div>
    );
  };

  /**
   * Mock Form.Row sub-component
   */
  const FormRow = ({
    children,
    className,
  }: {
    children: React.ReactNode;
    className?: string;
  }) => (
    <div className={className} data-testid="form-row">
      {children}
    </div>
  );

  /**
   * Mock Form.SubmitErrorBlock sub-component
   */
  const MockFormSubmitErrorBlock = ({
    errors,
  }: {
    errors: string | string[];
  }) => {
    const errorsArray = Array.isArray(errors) ? errors : [errors];
    return (
      <div className="submit-error" data-testid="submit-error-block">
        {errorsArray.map((error: string) => (
          <span
            key={error}
            data-testid={`submit-error-${error.replace(/\s+/g, "-").toLowerCase()}`}
          >
            {error}
          </span>
        ))}
      </div>
    );
  };

  /**
   * Mock Form component with static sub-components
   */
  const FormBase = ({
    children,
    onSubmit,
    className,
    noValidate,
  }: {
    children: React.ReactNode;
    onSubmit?: (e: React.FormEvent) => void;
    className?: string;
    noValidate?: boolean;
  }) => (
    <form
      onSubmit={onSubmit}
      className={className}
      noValidate={noValidate}
      data-testid="register-form"
    >
      {children}
    </form>
  );

  // Attach static sub-components to Form
  const Form = Object.assign(FormBase, {
    Row: FormRow,
    SubmitErrorBlock: MockFormSubmitErrorBlock,
  });

  return {
    Button,
    ControlledInput,
    Form,
  };
});

describe("RegisterForm Component", () => {
  /**
   * Default mock return values for useRegisterForm hook
   */
  const defaultMockReturn = {
    formData: {
      firstName: "",
      lastName: "",
      username: "",
      email: "",
      password: "",
      passwordConfirm: "",
    },
    errors: {} as Record<string, string | undefined>,
    isSubmitting: false,
    touched: {
      firstName: false,
      lastName: false,
      username: false,
      email: false,
      password: false,
      passwordConfirm: false,
    },
    resetForm: vi.fn(),
    handleChange: vi.fn(() => vi.fn()),
    handleBlur: vi.fn(() => vi.fn()),
    handleSubmit: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useRegisterForm).mockReturnValue(defaultMockReturn);
  });

  describe("Rendering", () => {
    /**
     * @description Should render all form fields correctly
     * @scenario Rendering RegisterForm with default props should display all input fields
     * @expected All 6 input fields should be present
     */
    it("should render all required input fields", () => {
      render(<RegisterForm />);

      expect(screen.getByTestId("input-имя")).toBeInTheDocument();
      expect(screen.getByTestId("input-фамилия")).toBeInTheDocument();
      expect(screen.getByTestId("input-логин")).toBeInTheDocument();
      expect(screen.getByTestId("input-email")).toBeInTheDocument();
      expect(screen.getByTestId("input-пароль")).toBeInTheDocument();
      expect(
        screen.getByTestId("input-подтверждение пароля"),
      ).toBeInTheDocument();
    });

    /**
     * @description Should render submit button with correct text
     * @scenario Rendering RegisterForm should display submit button with registration text
     * @expected Button with text "Зарегистрироваться" should be present
     */
    it("should render submit button with registration text", () => {
      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toBeInTheDocument();
      expect(submitButton).toHaveTextContent("Зарегистрироваться");
    });

    /**
     * @description Should render form with correct structure
     * @scenario Rendering RegisterForm should create proper form element
     * @expected Form element with register-form class should be present
     */
    it("should render form element with correct class", () => {
      render(<RegisterForm />);

      const formElement = screen.getByTestId("register-form");
      expect(formElement).toBeInTheDocument();
      expect(formElement).toHaveClass("register-form");
    });

    /**
     * @description Should render double row for name fields
     * @scenario Rendering RegisterForm should group firstName and lastName in one row
     * @expected Form row with double class should contain name inputs
     */
    it("should render name fields in double row layout", () => {
      render(<RegisterForm />);

      const formRow = screen.getByTestId("form-row");
      expect(formRow).toBeInTheDocument();
      expect(formRow).toHaveClass(
        "register-form__row register-form__row--double",
      );
    });
  });

  describe("Form Input Interaction", () => {
    /**
     * @description Should handle first name input changes
     * @scenario User types in first name field should trigger handleChange
     * @expected handleChange should be called with firstName field name
     */
    it("should handle first name input change", async () => {
      const user = userEvent.setup();
      const handleChangeMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleChange: handleChangeMock,
      });

      render(<RegisterForm />);

      const firstNameInput = screen.getByTestId("input-имя");
      await user.type(firstNameInput, "John");

      expect(handleChangeMock).toHaveBeenCalledWith("firstName");
    });

    /**
     * @description Should handle last name input changes
     * @scenario User types in last name field should trigger handleChange
     * @expected handleChange should be called with lastName field name
     */
    it("should handle last name input change", async () => {
      const user = userEvent.setup();
      const handleChangeMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleChange: handleChangeMock,
      });

      render(<RegisterForm />);

      const lastNameInput = screen.getByTestId("input-фамилия");
      await user.type(lastNameInput, "Doe");

      expect(handleChangeMock).toHaveBeenCalledWith("lastName");
    });

    /**
     * @description Should handle username input changes
     * @scenario User types in username field should trigger handleChange
     * @expected handleChange should be called with username field name
     */
    it("should handle username input change", async () => {
      const user = userEvent.setup();
      const handleChangeMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleChange: handleChangeMock,
      });

      render(<RegisterForm />);

      const usernameInput = screen.getByTestId("input-логин");
      await user.type(usernameInput, "johndoe");

      expect(handleChangeMock).toHaveBeenCalledWith("username");
    });

    /**
     * @description Should handle email input changes
     * @scenario User types in email field should trigger handleChange
     * @expected handleChange should be called with email field name
     */
    it("should handle email input change", async () => {
      const user = userEvent.setup();
      const handleChangeMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleChange: handleChangeMock,
      });

      render(<RegisterForm />);

      const emailInput = screen.getByTestId("input-email");
      await user.type(emailInput, "john@example.com");

      expect(handleChangeMock).toHaveBeenCalledWith("email");
    });

    /**
     * @description Should handle password input changes
     * @scenario User types in password field should trigger handleChange
     * @expected handleChange should be called with password field name
     */
    it("should handle password input change", async () => {
      const user = userEvent.setup();
      const handleChangeMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleChange: handleChangeMock,
      });

      render(<RegisterForm />);

      const passwordInput = screen.getByTestId("input-пароль");
      await user.type(passwordInput, "SecurePass123");

      expect(handleChangeMock).toHaveBeenCalledWith("password");
    });

    /**
     * @description Should handle password confirm input changes
     * @scenario User types in password confirm field should trigger handleChange
     * @expected handleChange should be called with passwordConfirm field name
     */
    it("should handle password confirm input change", async () => {
      const user = userEvent.setup();
      const handleChangeMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleChange: handleChangeMock,
      });

      render(<RegisterForm />);

      const passwordConfirmInput = screen.getByTestId(
        "input-подтверждение пароля",
      );
      await user.type(passwordConfirmInput, "SecurePass123");

      expect(handleChangeMock).toHaveBeenCalledWith("passwordConfirm");
    });

    /**
     * @description Should handle blur events on all inputs
     * @scenario User blurs from input field should trigger handleBlur
     * @expected handleBlur should be called with corresponding field name
     */
    it("should handle blur events on inputs", async () => {
      const user = userEvent.setup();
      const handleBlurMock = vi.fn(() => vi.fn());

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleBlur: handleBlurMock,
      });

      render(<RegisterForm />);

      const firstNameInput = screen.getByTestId("input-имя");
      await user.click(firstNameInput);
      await user.tab();

      expect(handleBlurMock).toHaveBeenCalledWith("firstName");
    });
  });

  describe("Form Validation Errors", () => {
    /**
     * @description Should display field validation errors
     * @scenario Form has validation errors should display error messages
     * @expected Error messages should be visible for each invalid field
     */
    it("should display validation errors for fields", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        errors: {
          firstName: "First name is required",
          email: "Invalid email format",
          password: "Password must be at least 8 characters",
        },
      });

      render(<RegisterForm />);

      expect(screen.getByTestId("error-имя")).toBeInTheDocument();
      expect(screen.getByTestId("error-имя")).toHaveTextContent(
        "First name is required",
      );
      expect(screen.getByTestId("error-email")).toBeInTheDocument();
      expect(screen.getByTestId("error-пароль")).toBeInTheDocument();
    });

    /**
     * @description Should display submit error block
     * @scenario Form submission fails should display submit error block
     * @expected SubmitErrorBlock should be rendered with error messages
     */
    it("should display submit error block on submission error", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        errors: {
          submit: "Registration failed",
        },
      });

      render(<RegisterForm />);

      expect(screen.getByTestId("submit-error-block")).toBeInTheDocument();
    });

    /**
     * @description Should not display errors when none exist
     * @scenario Form has no validation errors should not show error messages
     * @expected No error elements should be present in the DOM
     */
    it("should not display errors when validation passes", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        errors: {},
      });

      render(<RegisterForm />);

      expect(
        screen.queryByTestId("submit-error-block"),
      ).not.toBeInTheDocument();
    });
  });

  describe("Form Submission", () => {
    /**
     * @description Should call handleSubmit on form submit
     * @scenario User clicks submit button should trigger form submission
     * @expected handleSubmit should be called once
     */
    it("should call handleSubmit on form submission", async () => {
      const user = userEvent.setup();
      const handleSubmitMock = vi.fn();

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        handleSubmit: handleSubmitMock,
      });

      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      await user.click(submitButton);

      expect(handleSubmitMock).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should prevent submission when submitting
     * @scenario Form is in submitting state should disable submit button
     * @expected Submit button should be disabled during submission
     */
    it("should disable submit button during submission", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        isSubmitting: true,
      });

      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toBeDisabled();
    });

    /**
     * @description Should show loading state during submission
     * @scenario Form is submitting should display loading indicator
     * @expected Submit button should have loading prop set to true
     */
    it("should show loading state on submit button", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        isSubmitting: true,
      });

      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toHaveAttribute("data-loading", "true");
    });

    /**
     * @description Should disable all inputs during submission
     * @scenario Form is submitting should disable all input fields
     * @expected All input fields should have disabled attribute
     */
    it("should disable all inputs during submission", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        isSubmitting: true,
      });

      render(<RegisterForm />);

      const inputs = screen.getAllByRole("textbox");
      inputs.forEach((input) => {
        expect(input).toBeDisabled();
      });
    });
  });

  describe("Callbacks", () => {
    /**
     * @description Should pass onSuccess callback to hook
     * @scenario RegisterForm receives onSuccess prop should pass it to useRegisterForm
     * @expected useRegisterForm should receive onSuccess callback
     */
    it("should pass onSuccess callback to useRegisterForm", () => {
      const onSuccessMock = vi.fn();

      render(<RegisterForm onSuccess={onSuccessMock} />);

      expect(vi.mocked(useRegisterForm)).toHaveBeenCalledWith({
        onSuccess: onSuccessMock,
        onError: undefined,
      });
    });

    /**
     * @description Should pass onError callback to hook
     * @scenario RegisterForm receives onError prop should pass it to useRegisterForm
     * @expected useRegisterForm should receive onError callback
     */
    it("should pass onError callback to useRegisterForm", () => {
      const onErrorMock = vi.fn();

      render(<RegisterForm onError={onErrorMock} />);

      expect(vi.mocked(useRegisterForm)).toHaveBeenCalledWith({
        onSuccess: undefined,
        onError: onErrorMock,
      });
    });

    /**
     * @description Should work without callbacks
     * @scenario RegisterForm rendered without callbacks should work correctly
     * @expected useRegisterForm should receive undefined for both callbacks
     */
    it("should work without optional callbacks", () => {
      render(<RegisterForm />);

      expect(vi.mocked(useRegisterForm)).toHaveBeenCalledWith({
        onSuccess: undefined,
        onError: undefined,
      });
    });
  });

  describe("Input Attributes", () => {
    /**
     * @description Should set correct autocomplete attributes
     * @scenario Each input field should have appropriate autocomplete value
     * @expected Autocomplete attributes should match field purpose
     */
    it("should set correct autocomplete attributes", () => {
      render(<RegisterForm />);

      expect(screen.getByTestId("input-имя")).toHaveAttribute(
        "autocomplete",
        "given-name",
      );
      expect(screen.getByTestId("input-фамилия")).toHaveAttribute(
        "autocomplete",
        "family-name",
      );
      expect(screen.getByTestId("input-логин")).toHaveAttribute(
        "autocomplete",
        "username",
      );
      expect(screen.getByTestId("input-email")).toHaveAttribute(
        "autocomplete",
        "email",
      );
      expect(screen.getByTestId("input-пароль")).toHaveAttribute(
        "autocomplete",
        "new-password",
      );
      expect(screen.getByTestId("input-подтверждение пароля")).toHaveAttribute(
        "autocomplete",
        "new-password",
      );
    });

    /**
     * @description Should set required attribute on all inputs
     * @scenario All form fields are mandatory should have required attribute
     * @expected All input fields should have required attribute set
     */
    it("should set required attribute on all inputs", () => {
      render(<RegisterForm />);

      const inputs = screen.getAllByRole("textbox");
      inputs.forEach((input) => {
        expect(input).toHaveAttribute("required");
      });
    });

    /**
     * @description Should set correct input types
     * @scenario Password and email fields should have appropriate type attributes
     * @expected Email and password inputs should have correct type values
     */
    it("should set correct input types", () => {
      render(<RegisterForm />);

      expect(screen.getByTestId("input-email")).toHaveAttribute(
        "type",
        "email",
      );
      expect(screen.getByTestId("input-пароль")).toHaveAttribute(
        "type",
        "password",
      );
      expect(screen.getByTestId("input-подтверждение пароля")).toHaveAttribute(
        "type",
        "password",
      );
    });

    /**
     * @description Should set placeholders for all inputs
     * @scenario All inputs should have descriptive placeholder text
     * @expected Each input should display appropriate placeholder
     */
    it("should set placeholders for all inputs", () => {
      render(<RegisterForm />);

      expect(screen.getByTestId("input-имя")).toHaveAttribute(
        "placeholder",
        "Введите имя",
      );
      expect(screen.getByTestId("input-фамилия")).toHaveAttribute(
        "placeholder",
        "Введите фамилию",
      );
      expect(screen.getByTestId("input-логин")).toHaveAttribute(
        "placeholder",
        "Придумайте логин",
      );
      expect(screen.getByTestId("input-email")).toHaveAttribute(
        "placeholder",
        "Введите email",
      );
      expect(screen.getByTestId("input-пароль")).toHaveAttribute(
        "placeholder",
        "Придумайте пароль",
      );
      expect(screen.getByTestId("input-подтверждение пароля")).toHaveAttribute(
        "placeholder",
        "Повторите пароль",
      );
    });
  });

  describe("Button Configuration", () => {
    /**
     * @description Should configure submit button as primary variant
     * @scenario Submit button should use primary variant styling
     * @expected Button should have primary variant attribute
     */
    it("should have primary variant on submit button", () => {
      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toHaveAttribute("data-variant", "primary");
    });

    /**
     * @description Should set button size to large
     * @scenario Submit button should use large size for better UX
     * @expected Button should have large size attribute
     */
    it("should have large size on submit button", () => {
      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toHaveAttribute("data-size", "large");
    });

    /**
     * @description Should set button to full width
     * @scenario Submit button should span full container width
     * @expected Button should have fullWidth attribute set
     */
    it("should have full width on submit button", () => {
      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toHaveAttribute("data-full-width", "true");
    });

    /**
     * @description Should set button type to submit
     * @scenario Submit button should trigger form submission
     * @expected Button should have type attribute set to submit
     */
    it("should have submit type on button", () => {
      render(<RegisterForm />);

      const submitButton = screen.getByTestId("submit-button");
      expect(submitButton).toHaveAttribute("type", "submit");
    });
  });

  describe("Form Configuration", () => {
    /**
     * @description Should disable browser validation
     * @scenario Form should use custom validation logic
     * @expected noValidate attribute should be set on form element
     */
    it("should have noValidate attribute on form", () => {
      render(<RegisterForm />);

      const formElement = screen.getByTestId("register-form");
      expect(formElement).toHaveAttribute("novalidate");
    });

    /**
     * @description Should populate form data from hook
     * @scenario Hook provides form data should display in inputs
     * @expected Input values should match formData from hook
     */
    it("should populate inputs with form data", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        formData: {
          firstName: "John",
          lastName: "Doe",
          username: "johndoe",
          email: "john@example.com",
          password: "SecurePass123",
          passwordConfirm: "SecurePass123",
        },
      });

      render(<RegisterForm />);

      expect(screen.getByTestId("input-имя")).toHaveValue("John");
      expect(screen.getByTestId("input-фамилия")).toHaveValue("Doe");
      expect(screen.getByTestId("input-логин")).toHaveValue("johndoe");
      expect(screen.getByTestId("input-email")).toHaveValue("john@example.com");
    });
  });

  describe("Edge Cases", () => {
    /**
     * @description Should handle empty error object
     * @scenario Errors object is empty should not render error components
     * @expected No error elements should be rendered
     */
    it("should handle empty errors object gracefully", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        errors: {},
      });

      render(<RegisterForm />);

      expect(
        screen.queryByTestId("submit-error-block"),
      ).not.toBeInTheDocument();
    });

    /**
     * @description Should handle null callbacks
     * @scenario Callbacks are null should not cause errors
     * @expected Component should render without errors
     */
    it("should handle undefined callbacks", () => {
      expect(() => {
        render(<RegisterForm />);
      }).not.toThrow();
    });

    /**
     * @description Should handle loading state transition
     * @scenario isSubmitting changes from false to true should update UI
     * @expected Button should become disabled when submitting starts
     */
    it("should handle submitting state transition", () => {
      const { rerender } = render(<RegisterForm />);

      expect(screen.getByTestId("submit-button")).not.toBeDisabled();

      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        isSubmitting: true,
      });

      rerender(<RegisterForm />);

      expect(screen.getByTestId("submit-button")).toBeDisabled();
    });

    /**
     * @description Should handle multiple validation errors
     * @scenario Multiple fields have errors should display all
     * @expected All error messages should be visible simultaneously
     */
    it("should display multiple validation errors simultaneously", () => {
      vi.mocked(useRegisterForm).mockReturnValue({
        ...defaultMockReturn,
        errors: {
          firstName: "Required",
          lastName: "Required",
          username: "Required",
          email: "Required",
          password: "Required",
          passwordConfirm: "Required",
        },
      });

      render(<RegisterForm />);

      expect(screen.getByTestId("error-имя")).toBeInTheDocument();
      expect(screen.getByTestId("error-фамилия")).toBeInTheDocument();
      expect(screen.getByTestId("error-логин")).toBeInTheDocument();
      expect(screen.getByTestId("error-email")).toBeInTheDocument();
      expect(screen.getByTestId("error-пароль")).toBeInTheDocument();
      expect(
        screen.getByTestId("error-подтверждение пароля"),
      ).toBeInTheDocument();
    });
  });
});
