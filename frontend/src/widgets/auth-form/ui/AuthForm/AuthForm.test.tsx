import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  IUseLoginFormProps,
  IUseRegisterFormProps,
} from "@/features/auth";

import type { ITabSwitcherProps } from "../../lib/tabs.config";
import { AuthForm } from "./AuthForm";

// =============================================================================
// MOCKS CONFIGURATION
// =============================================================================

// Mock for '@/features/auth/login-by-email'
vi.mock("@/features/auth/login-by-email", () => ({
  LoginForm: ({ onSuccess, onError }: IUseLoginFormProps) => (
    <div data-testid="login-form">
      <button
        type="button"
        data-testid="login-submit-success"
        onClick={() => onSuccess?.()}
      >
        Login Success
      </button>
      <button
        type="button"
        data-testid="login-submit-error"
        onClick={() => onError?.("Login error")}
      >
        Login Error
      </button>
    </div>
  ),
}));

// Mock for '@/features/auth/register-by-email'
vi.mock("@/features/auth/register-by-email", () => ({
  RegisterForm: ({ onSuccess, onError }: IUseRegisterFormProps) => (
    <div data-testid="register-form">
      <button
        type="button"
        data-testid="register-submit-success"
        onClick={() => onSuccess?.()}
      >
        Register Success
      </button>
      <button
        type="button"
        data-testid="register-submit-error"
        onClick={() => onError?.("Register error")}
      >
        Register Error
      </button>
    </div>
  ),
}));

// Mock for TabsSwitcher component
vi.mock("../TabSwitcher/TabsSwitcher", () => ({
  TabsSwitcher: ({ activeTab, onTabChange, disabled }: ITabSwitcherProps) => (
    <div data-testid="tabs-switcher">
      <button
        type="button"
        data-testid="tab-login"
        className={activeTab === "login" ? "active" : ""}
        onClick={() => !disabled && onTabChange("login")}
      >
        Вход
      </button>
      <button
        type="button"
        data-testid="tab-register"
        className={activeTab === "register" ? "active" : ""}
        onClick={() => !disabled && onTabChange("register")}
      >
        Регистрация
      </button>
    </div>
  ),
}));

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Tab params for URL
 */
const TAB_PARAMS = {
  login: "?tab=login",
  register: "?tab=register",
  invalid: "?tab=invalid",
};

/**
 * Helper to render AuthForm with Router context
 * @param initialPath - Initial path with optional query params
 * @returns Render result and router instance
 */
const renderWithRouter = (initialPath = "/") => {
  const router = createMemoryRouter(
    [
      {
        path: "*",
        element: <AuthForm />,
      },
    ],
    {
      initialEntries: [initialPath],
    },
  );
  return {
    router,
    ...render(<RouterProvider router={router} />),
  };
};

/**
 * Helper to render AuthForm with callbacks
 *
 * @param onSuccess - Success callback
 * @param onError - Error callback
 * @param initialPath - Initial path
 *
 * @returns Render result
 */
const renderWithCallbacks = (
  onSuccess?: () => void,
  onError?: (error: string) => void,
  initialPath = "/",
) => {
  const router = createMemoryRouter(
    [
      {
        path: "*",
        element: <AuthForm onSuccess={onSuccess} onError={onError} />,
      },
    ],
    {
      initialEntries: [initialPath],
    },
  );
  return render(<RouterProvider router={router} />);
};

// =============================================================================
// TEST SUITE
// =============================================================================

describe("AuthForm", () => {
  const mockOnSuccess = vi.fn();
  const mockOnError = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    mockOnSuccess.mockClear();
    mockOnError.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Rendering Tests - Initial State
  // ---------------------------------------------------------------------------

  describe("Rendering - Initial State", () => {
    /**
     * @description Should render LoginForm by default
     * @scenario Component rendered without query params should show login form
     * @expected Login form is visible, register form is not in document
     */
    it("should render LoginForm by default", () => {
      renderWithRouter();

      expect(screen.getByTestId("login-form")).toBeInTheDocument();
      expect(screen.queryByTestId("register-form")).not.toBeInTheDocument();
    });

    /**
     * @description Should render RegisterForm when tab=register in URL
     * @scenario Component rendered with ?tab=register should show register form
     * @expected Register form is visible, login form is not in document
     */
    it("should render RegisterForm when tab=register in URL", () => {
      renderWithRouter(TAB_PARAMS.register);

      expect(screen.getByTestId("register-form")).toBeInTheDocument();
      expect(screen.queryByTestId("login-form")).not.toBeInTheDocument();
    });

    /**
     * @description Should render TabsSwitcher component
     * @scenario Component should always render tab switcher
     * @expected TabsSwitcher with data-testid is present
     */
    it("should render TabsSwitcher component", () => {
      renderWithRouter();

      expect(screen.getByTestId("tabs-switcher")).toBeInTheDocument();
    });

    /**
     * @description Should render panel with correct ARIA attributes for login
     * @scenario Default active tab is "login"
     * @expected Panel has id="panel-login", role="tabpanel", aria-labelledby="tab-login"
     */
    it("should render panel with correct ARIA attributes for login", () => {
      renderWithRouter();

      const panel = screen.getByRole("tabpanel");
      expect(panel).toHaveAttribute("id", "panel-login");
      expect(panel).toHaveAttribute("role", "tabpanel");
      expect(panel).toHaveAttribute("aria-labelledby", "tab-login");
    });

    /**
     * @description Should render panel with correct ARIA attributes for register
     * @scenario Active tab is "register" from URL params
     * @expected Panel has id="panel-register", role="tabpanel", aria-labelledby="tab-register"
     */
    it("should render panel with correct ARIA attributes for register", () => {
      renderWithRouter(TAB_PARAMS.register);

      const panel = screen.getByRole("tabpanel");
      expect(panel).toHaveAttribute("id", "panel-register");
      expect(panel).toHaveAttribute("role", "tabpanel");
      expect(panel).toHaveAttribute("aria-labelledby", "tab-register");
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests - Tab Switching
  // ---------------------------------------------------------------------------

  describe("Interaction - Tab Switching", () => {
    /**
     * @description Should switch to register form when register tab is clicked
     * @scenario User clicks on register tab in TabsSwitcher
     * @expected Register form becomes visible, login form is hidden, URL updated
     */
    it("should switch to register form when register tab is clicked", async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter();

      expect(screen.getByTestId("login-form")).toBeInTheDocument();

      const registerTab = screen.getByTestId("tab-register");
      await user.click(registerTab);

      await waitFor(() => {
        expect(screen.getByTestId("register-form")).toBeInTheDocument();
        expect(screen.queryByTestId("login-form")).not.toBeInTheDocument();
      });

      expect(router.state.location.search).toBe(TAB_PARAMS.register);
    });

    /**
     * @description Should switch to login form when login tab is clicked
     * @scenario User is on register tab and clicks login tab
     * @expected Login form becomes visible, register form is hidden, URL cleared
     */
    it("should switch to login form when login tab is clicked", async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter(TAB_PARAMS.register);

      expect(screen.getByTestId("register-form")).toBeInTheDocument();

      const loginTab = screen.getByTestId("tab-login");
      await user.click(loginTab);

      await waitFor(() => {
        expect(screen.getByTestId("login-form")).toBeInTheDocument();
        expect(screen.queryByTestId("register-form")).not.toBeInTheDocument();
      });

      expect(router.state.location.search).toBe("");
    });

    /**
     * @description Should update URL params when tab changes
     * @scenario Tab switch should modify search params via setSearchParams
     * @expected URL contains ?tab=register after switching to register tab
     */
    it("should update URL params when tab changes", async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter();

      const registerTab = screen.getByTestId("tab-register");
      await user.click(registerTab);

      await waitFor(() => {
        expect(router.state.location.search).toBe(TAB_PARAMS.register);
      });
    });

    /**
     * @description Should clear URL params when switching to login tab
     * @scenario Switching from register to login should remove tab param
     * @expected URL search is empty after switching to login
     */
    it("should clear URL params when switching to login tab", async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter(TAB_PARAMS.register);

      expect(router.state.location.search).toBe(TAB_PARAMS.register);

      const loginTab = screen.getByTestId("tab-login");
      await user.click(loginTab);

      await waitFor(() => {
        expect(router.state.location.search).toBe("");
      });
    });

    /**
     * @description Should update panel ARIA attributes after tab switch
     * @scenario Tab change should update panel id and aria-labelledby
     * @expected Panel attributes reflect the new active tab
     */
    it("should update panel ARIA attributes after tab switch", async () => {
      const user = userEvent.setup();
      renderWithRouter();

      let panel = screen.getByRole("tabpanel");
      expect(panel).toHaveAttribute("id", "panel-login");
      expect(panel).toHaveAttribute("aria-labelledby", "tab-login");

      const registerTab = screen.getByTestId("tab-register");
      await user.click(registerTab);

      await waitFor(() => {
        panel = screen.getByRole("tabpanel");
        expect(panel).toHaveAttribute("id", "panel-register");
        expect(panel).toHaveAttribute("aria-labelledby", "tab-register");
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Callback Tests - onSuccess/onError
  // ---------------------------------------------------------------------------

  describe("Callbacks - onSuccess/onError", () => {
    /**
     * @description Should pass onSuccess callback to LoginForm
     * @scenario LoginForm submit success button clicked with onSuccess provided
     * @expected mockOnSuccess is called once, mockOnError is not called
     */
    it("should pass onSuccess callback to LoginForm", async () => {
      const user = userEvent.setup();
      renderWithCallbacks(mockOnSuccess, mockOnError);

      const submitButton = screen.getByTestId("login-submit-success");
      await user.click(submitButton);

      expect(mockOnSuccess).toHaveBeenCalledTimes(1);
      expect(mockOnError).not.toHaveBeenCalled();
    });

    /**
     * @description Should pass onSuccess callback to RegisterForm
     * @scenario RegisterForm submit success button clicked with onSuccess provided
     * @expected mockOnSuccess is called once, mockOnError is not called
     */
    it("should pass onSuccess callback to RegisterForm", async () => {
      const user = userEvent.setup();
      renderWithCallbacks(mockOnSuccess, mockOnError, TAB_PARAMS.register);

      const submitButton = screen.getByTestId("register-submit-success");
      await user.click(submitButton);

      expect(mockOnSuccess).toHaveBeenCalledTimes(1);
      expect(mockOnError).not.toHaveBeenCalled();
    });

    /**
     * @description Should pass onError callback to LoginForm
     * @scenario LoginForm submit error button clicked with onError provided
     * @expected mockOnError is called with error message
     */
    it("should pass onError callback to LoginForm", async () => {
      const user = userEvent.setup();
      renderWithCallbacks(mockOnSuccess, mockOnError);

      const submitButton = screen.getByTestId("login-submit-error");
      await user.click(submitButton);

      expect(mockOnSuccess).not.toHaveBeenCalled();
      expect(mockOnError).toHaveBeenCalledWith("Login error");
    });

    /**
     * @description Should pass onError callback to RegisterForm
     * @scenario RegisterForm submit error button clicked with onError provided
     * @expected mockOnError is called with error message
     */
    it("should pass onError callback to RegisterForm", async () => {
      const user = userEvent.setup();
      renderWithCallbacks(mockOnSuccess, mockOnError, TAB_PARAMS.register);

      const submitButton = screen.getByTestId("register-submit-error");
      await user.click(submitButton);

      expect(mockOnSuccess).not.toHaveBeenCalled();
      expect(mockOnError).toHaveBeenCalledWith("Register error");
    });

    /**
     * @description Should handle undefined onSuccess callback gracefully
     * @scenario LoginForm submit with no onSuccess provided
     * @expected No errors thrown, component functions normally
     */
    it("should handle undefined onSuccess callback gracefully", async () => {
      const user = userEvent.setup();
      renderWithCallbacks(undefined, mockOnError);

      const submitButton = screen.getByTestId("login-submit-success");

      await expect(user.click(submitButton)).resolves.not.toThrow();
      expect(screen.getByTestId("login-form")).toBeInTheDocument();
    });

    /**
     * @description Should handle undefined onError callback gracefully
     * @scenario LoginForm submit with no onError provided
     * @expected No errors thrown, component functions normally
     */
    it("should handle undefined onError callback gracefully", async () => {
      const user = userEvent.setup();
      renderWithCallbacks(mockOnSuccess, undefined);

      const submitButton = screen.getByTestId("login-submit-error");

      await expect(user.click(submitButton)).resolves.not.toThrow();
      expect(screen.getByTestId("login-form")).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // Integration Tests
  // ---------------------------------------------------------------------------

  describe("Integration", () => {
    /**
     * @description Should maintain state after tab switch and form interaction
     * @scenario Switch tab, interact with form, verify state consistency
     * @expected Component state and URL remain synchronized
     */
    it("should maintain state after tab switch and form interaction", async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter();

      // Start on login
      expect(screen.getByTestId("login-form")).toBeInTheDocument();

      // Switch to register
      await user.click(screen.getByTestId("tab-register"));
      await waitFor(() => {
        expect(screen.getByTestId("register-form")).toBeInTheDocument();
        expect(router.state.location.search).toBe(TAB_PARAMS.register);
      });

      // Switch back to login
      await user.click(screen.getByTestId("tab-login"));
      await waitFor(() => {
        expect(screen.getByTestId("login-form")).toBeInTheDocument();
        expect(router.state.location.search).toBe("");
      });
    });

    /**
     * @description Should render with container structure
     * @scenario Component should render section with auth-form class
     * @expected Parent element has "auth-form" class
     */
    it("should render with container structure", () => {
      renderWithRouter();

      const container = document.querySelector("section.auth-form");
      expect(container).toBeInTheDocument();
    });

    /**
     * @description Should handle rapid tab clicks without errors
     * @scenario User clicks multiple tabs in quick succession
     * @expected Component handles all clicks without crashing
     */
    it("should handle rapid tab clicks without errors", async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const loginTab = screen.getByTestId("tab-login");
      const registerTab = screen.getByTestId("tab-register");

      await user.click(registerTab);
      await user.click(loginTab);
      await user.click(registerTab);
      await user.click(loginTab);

      // Should end on login form without errors
      expect(screen.getByTestId("login-form")).toBeInTheDocument();
    });

    /**
     * @description Should initialize activeTab from URL on first render
     * @scenario Component mounted with ?tab=register should start on register
     * @expected Register form is rendered immediately, no flash of login
     */
    it("should initialize activeTab from URL on first render", () => {
      renderWithRouter(TAB_PARAMS.register);

      // Register form should be visible immediately
      expect(screen.getByTestId("register-form")).toBeInTheDocument();
      expect(screen.queryByTestId("login-form")).not.toBeInTheDocument();
    });

    /**
     * @description Should use DEFAULT_AUTH_TAB when tab param is invalid
     * @scenario URL has ?tab=invalid value
     * @expected Component falls back to login form (default)
     */
    it("should use DEFAULT_AUTH_TAB when tab param is invalid", () => {
      renderWithRouter(TAB_PARAMS.invalid);

      // Should default to login form
      expect(screen.getByTestId("login-form")).toBeInTheDocument();
      expect(screen.queryByTestId("register-form")).not.toBeInTheDocument();
    });
  });
});
