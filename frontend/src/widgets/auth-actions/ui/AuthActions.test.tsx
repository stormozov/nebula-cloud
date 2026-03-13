import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthActions } from "./AuthActions";

// ============================================================================
// MOCKS CONFIGURATION
// ============================================================================

// Mock for 'classnames' utility with proper object syntax support
vi.mock("classnames", () => ({
  default: vi.fn(
    (...classes: (string | undefined | Record<string, boolean | string>)[]) => {
      const processedClasses: string[] = [];

      for (const cls of classes) {
        if (typeof cls === "string" && cls) {
          processedClasses.push(cls);
        } else if (typeof cls === "object" && cls !== null) {
          for (const [key, value] of Object.entries(cls)) {
            // Handle the buggy pattern: { className: "actual-class-name" }
            if (key === "className" && typeof value === "string" && value) {
              processedClasses.push(value);
            } else if (
              value &&
              typeof key === "string" &&
              key &&
              key !== "className"
            ) {
              processedClasses.push(key);
            }
          }
        }
      }

      return processedClasses.join(" ");
    },
  ),
}));

// Mock for '@/features/auth' - LoginButton and RegisterButton
vi.mock("@/features/auth", () => ({
  LoginButton: ({
    children,
    variant,
    size,
  }: {
    children: React.ReactNode;
    variant?: string;
    size?: string;
    _className?: string;
    [key: string]: unknown;
  }) => (
    <button
      type="button"
      data-testid="login-button"
      data-variant={variant}
      data-size={size}
    >
      {children}
    </button>
  ),
  RegisterButton: ({
    children,
    variant,
    size,
  }: {
    children: React.ReactNode;
    variant?: string;
    size?: string;
    _className?: string;
    [key: string]: unknown;
  }) => (
    <button
      type="button"
      data-testid="register-button"
      data-variant={variant}
      data-size={size}
    >
      {children}
    </button>
  ),
}));

// ============================================================================
// TEST HELPERS
// ============================================================================

/**
 * Helper to get the container div by class name
 * @returns The container element
 */
const getContainer = () =>
  document.querySelector(".auth-actions") as HTMLElement;

// ============================================================================
// TEST SUITE
// ============================================================================

describe("AuthActions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Rendering Tests
  // -------------------------------------------------------------------------

  describe("Rendering", () => {
    /**
     * @description Should render with default props correctly
     * @scenario Rendering component without any props should use default values
     * @expected Both LoginButton and RegisterButton are rendered, size is "medium"
     */
    it("should render with default props correctly", () => {
      render(<AuthActions />);

      const loginButton = screen.getByTestId("login-button");
      const registerButton = screen.getByTestId("register-button");

      expect(loginButton).toBeInTheDocument();
      expect(registerButton).toBeInTheDocument();
      expect(loginButton).toHaveTextContent("Войти");
      expect(registerButton).toHaveTextContent("Зарегистрироваться");
    });

    /**
     * @description Should apply custom size prop to both buttons
     * @scenario Passing size="large" should propagate to both LoginButton and RegisterButton
     * @expected Both buttons have data-size="large"
     */
    it("should apply custom size prop to both buttons", () => {
      render(<AuthActions size="large" />);

      const loginButton = screen.getByTestId("login-button");
      const registerButton = screen.getByTestId("register-button");

      expect(loginButton).toHaveAttribute("data-size", "large");
      expect(registerButton).toHaveAttribute("data-size", "large");
    });

    /**
     * @description Should apply custom className to container
     * @scenario Passing className="custom-class" should be added to container
     * @expected Container classList contains "custom-class"
     */
    it("should apply custom className to container", () => {
      const customClass = "custom-class";
      render(<AuthActions className={customClass} />);

      const container = getContainer();
      expect(container.className).toContain(customClass);
    });

    /**
     * @description Should handle undefined className correctly
     * @scenario Passing undefined className should not add extra spaces
     * @expected Container classList contains only "auth-actions"
     */
    it("should handle undefined className correctly", () => {
      render(<AuthActions className={undefined} />);

      const container = getContainer();
      expect(container.className).toBe("auth-actions");
    });

    /**
     * @description Should render LoginButton with secondary variant
     * @scenario LoginButton should always use "secondary" variant
     * @expected LoginButton has data-variant="secondary"
     */
    it("should render LoginButton with secondary variant", () => {
      render(<AuthActions />);

      const loginButton = screen.getByTestId("login-button");
      expect(loginButton).toHaveAttribute("data-variant", "secondary");
    });

    /**
     * @description Should render RegisterButton with primary variant
     * @scenario RegisterButton should always use "primary" variant
     * @expected RegisterButton has data-variant="primary"
     */
    it("should render RegisterButton with primary variant", () => {
      render(<AuthActions />);

      const registerButton = screen.getByTestId("register-button");
      expect(registerButton).toHaveAttribute("data-variant", "primary");
    });
  });

  // -------------------------------------------------------------------------
  // Button Order Tests
  // -------------------------------------------------------------------------

  describe("Button Order", () => {
    /**
     * @description Should not apply reverse class by default
     * @scenario registerFirst is false by default
     * @expected Container classList does not contain "auth-actions--reverse"
     */
    it("should not apply reverse class by default", () => {
      render(<AuthActions />);

      const container = getContainer();
      expect(container.className).not.toContain("auth-actions--reverse");
    });

    /**
     * @description Should apply reverse class when registerFirst is true
     * @scenario Passing registerFirst={true} should add reverse modifier class
     * @expected Container classList contains "auth-actions--reverse"
     */
    it("should apply reverse class when registerFirst is true", () => {
      render(<AuthActions registerFirst={true} />);

      const container = getContainer();
      expect(container.className).toContain("auth-actions--reverse");
    });

    /**
     * @description Should not apply reverse class when registerFirst is false
     * @scenario Passing registerFirst={false} should not add reverse modifier class
     * @expected Container classList does not contain "auth-actions--reverse"
     */
    it("should not apply reverse class when registerFirst is false", () => {
      render(<AuthActions registerFirst={false} />);

      const container = getContainer();
      expect(container.className).not.toContain("auth-actions--reverse");
    });

    /**
     * @description Should maintain both buttons regardless of order
     * @scenario Changing registerFirst should not remove any buttons
     * @expected Both LoginButton and RegisterButton are present
     */
    it("should maintain both buttons regardless of order", () => {
      const { rerender } = render(<AuthActions registerFirst={false} />);

      expect(screen.getByTestId("login-button")).toBeInTheDocument();
      expect(screen.getByTestId("register-button")).toBeInTheDocument();

      rerender(<AuthActions registerFirst={true} />);

      expect(screen.getByTestId("login-button")).toBeInTheDocument();
      expect(screen.getByTestId("register-button")).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // Integration Tests
  // -------------------------------------------------------------------------

  describe("Integration", () => {
    /**
     * @description Should render with all custom props combined
     * @scenario Passing all props together should apply all correctly
     * @expected Container has correct classes, buttons have correct size
     */
    it("should render with all custom props combined", () => {
      render(
        <AuthActions
          registerFirst={true}
          size="large"
          className="custom-wrapper"
        />,
      );

      const container = getContainer();
      const loginButton = screen.getByTestId("login-button");
      const registerButton = screen.getByTestId("register-button");

      expect(container.className).toContain("auth-actions");
      expect(container.className).toContain("auth-actions--reverse");
      expect(container.className).toContain("custom-wrapper");
      expect(loginButton).toHaveAttribute("data-size", "large");
      expect(registerButton).toHaveAttribute("data-size", "large");
    });

    /**
     * @description Should render container with base class
     * @scenario Component should always have "auth-actions" base class
     * @expected Container classList contains "auth-actions"
     */
    it("should render container with base class", () => {
      render(<AuthActions />);

      const container = getContainer();
      expect(container.className).toContain("auth-actions");
    });

    /**
     * @description Should handle small size prop
     * @scenario Passing size="small" should propagate to both buttons
     * @expected Both buttons have data-size="small"
     */
    it("should handle small size prop", () => {
      render(<AuthActions size="small" />);

      const loginButton = screen.getByTestId("login-button");
      const registerButton = screen.getByTestId("register-button");

      expect(loginButton).toHaveAttribute("data-size", "small");
      expect(registerButton).toHaveAttribute("data-size", "small");
    });

    /**
     * @description Should handle large size prop
     * @scenario Passing size="large" should propagate to both buttons
     * @expected Both buttons have data-size="large"
     */
    it("should handle large size prop", () => {
      render(<AuthActions size="large" />);

      const loginButton = screen.getByTestId("login-button");
      const registerButton = screen.getByTestId("register-button");

      expect(loginButton).toHaveAttribute("data-size", "large");
      expect(registerButton).toHaveAttribute("data-size", "large");
    });

    /**
     * @description Should render buttons with correct text content
     * @scenario Buttons should display default text when no children provided
     * @expected LoginButton shows "Войти", RegisterButton shows "Зарегистрироваться"
     */
    it("should render buttons with correct text content", () => {
      render(<AuthActions />);

      const loginButton = screen.getByTestId("login-button");
      const registerButton = screen.getByTestId("register-button");

      expect(loginButton).toHaveTextContent("Войти");
      expect(registerButton).toHaveTextContent("Зарегистрироваться");
    });
  });
});
