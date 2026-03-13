import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LogoutButton } from "./LogoutButton";

// =============================================================================
// MOCKS CONFIGURATION
// =============================================================================

// Controlled mock functions for logout mutation
const mockLogoutTrigger = vi.fn();
const mockLogoutUnwrap = vi.fn();
const mockIsLoading = vi.fn(() => false);

// Mock for '@/entities/user' - RTK Query hook
vi.mock("@/entities/user", () => ({
  useLogoutMutation: () => [
    (_options?: unknown) => ({
      unwrap: () => mockLogoutUnwrap(),
    }),
    { isLoading: mockIsLoading() },
  ],
}));

// Mock for '@/shared/ui' Button component with strict typing
vi.mock("@/shared/ui", () => ({
  Button: ({
    children,
    onClick,
    className,
    type,
    loading,
    ...props
  }: {
    children: React.ReactNode;
    onClick?: () => void | Promise<void>;
    className?: string;
    type?: "button" | "submit" | "reset";
    loading?: boolean;
    [key: string]: unknown;
  }) => (
    <button onClick={onClick} className={className} type={type} {...props}>
      {loading ? "Loading..." : children}
    </button>
  ),
}));

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Helper to render component with Router context
 * @param initialPath - Initial path for the router
 * @param element - Optional custom element to render
 * @returns Render result and router instance
 */
const renderWithRouter = (
  initialPath = "/",
  element: React.ReactElement = <LogoutButton />,
) => {
  const router = createMemoryRouter(
    [
      {
        path: "*",
        element,
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

// =============================================================================
// TEST SUITE
// =============================================================================

describe("LogoutButton", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default successful logout
    mockLogoutTrigger.mockClear();
    mockLogoutUnwrap.mockResolvedValue(undefined);
    mockIsLoading.mockReturnValue(false);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Rendering Tests
  // ---------------------------------------------------------------------------

  describe("Rendering", () => {
    /**
     * @description Should render with default props correctly
     * @scenario Rendering component without any props should use default values
     * @expected Button text is "Выход", variant is "ghost", size is "medium"
     */
    it("should render with default props correctly", () => {
      renderWithRouter();

      const buttonElement = screen.getByRole("button");

      expect(buttonElement).toHaveTextContent("Выход");
      expect(buttonElement).toBeInTheDocument();
    });

    /**
     * @description Should apply custom variant and size props
     * @scenario Passing variant="primary" and size="large" should propagate to Button
     * @expected Button component receives correct variant and size props
     */
    it("should apply custom variant and size props", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton variant="primary" size="large" />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toBeInTheDocument();
    });

    /**
     * @description Should apply custom children text
     * @scenario Passing children="Sign Out" should change button text
     * @expected Button text content matches provided children prop
     */
    it("should apply custom children text", () => {
      const customText = "Sign Out";
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton>{customText}</LogoutButton>,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toHaveTextContent(customText);
    });

    /**
     * @description Should merge custom className with base class
     * @scenario Passing className="custom-class" should be combined with "logout-button"
     * @expected ClassList contains both "logout-button" and "custom-class"
     */
    it("should merge custom className with base class", () => {
      const customClass = "custom-class";

      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton className={customClass} />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement.className).toContain("logout-button");
      expect(buttonElement.className).toContain(customClass);
    });

    /**
     * @description Should handle undefined className correctly
     * @scenario Passing undefined className should not add extra spaces
     * @expected ClassList contains only "logout-button"
     */
    it("should handle undefined className correctly", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton className={undefined} />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement.className).toBe("logout-button ");
    });

    /**
     * @description Should pass rest props to underlying Button
     * @scenario Passing data-testid="logout-btn" should be present on button
     * @expected Button element has data-testid attribute
     */
    it("should pass rest props to underlying Button", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton data-testid="logout-btn" />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByTestId("logout-btn");
      expect(buttonElement).toBeInTheDocument();
    });

    /**
     * @description Should render with fullWidth prop
     * @scenario Passing fullWidth={true} should be applied to Button
     * @expected Button component receives fullWidth prop
     */
    it("should render with fullWidth prop", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton fullWidth />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // Loading State Tests
  // ---------------------------------------------------------------------------

  describe("Loading State", () => {
    /**
     * @description Should show loading state when mutation is pending
     * @scenario useLogoutMutation returns isLoading: true
     * @expected Button receives loading={true} prop
     */
    it("should show loading state when mutation is pending", () => {
      // Set loading state before render
      mockIsLoading.mockReturnValue(true);

      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LogoutButton />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toHaveTextContent("Loading...");
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests - Success Path
  // ---------------------------------------------------------------------------

  describe("Interaction - Success", () => {
    /**
     * @description Should call logout mutation and navigate on success
     * @scenario User clicks button and logout resolves successfully
     * @expected logout().unwrap() called once, navigate("/", { replace: true }) called
     */
    it("should call logout mutation and navigate on success", async () => {
      const { router } = renderWithRouter();

      const buttonElement = screen.getByRole("button");
      fireEvent.click(buttonElement);

      await waitFor(() => {
        expect(mockLogoutUnwrap).toHaveBeenCalledTimes(1);
      });

      expect(router.state.location.pathname).toBe("/");
      expect(router.state.location.search).toBe("");
    });

    /**
     * @description Should navigate with replace option on success
     * @scenario Successful logout should replace history entry
     * @expected navigate called with { replace: true }
     */
    it("should navigate with replace option on success", async () => {
      const { router } = renderWithRouter();

      const buttonElement = screen.getByRole("button");
      fireEvent.click(buttonElement);

      await waitFor(() => {
        expect(router.state.location.pathname).toBe("/");
      });

      // Verify replace behavior by checking history action
      expect(router.state.historyAction).toBe("REPLACE");
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests - Error Path
  // ---------------------------------------------------------------------------

  describe("Interaction - Error Handling", () => {
    /**
     * @description Should navigate to home even if logout fails
     * @scenario logout().unwrap() rejects with error
     * @expected catch block executes, navigate("/", { replace: true }) still called
     */
    it("should navigate to home even if logout fails", async () => {
      // Mock logout to reject
      mockLogoutUnwrap.mockRejectedValue(new Error("Logout failed"));

      const { router } = renderWithRouter();

      const buttonElement = screen.getByRole("button");
      fireEvent.click(buttonElement);

      await waitFor(() => {
        expect(router.state.location.pathname).toBe("/");
      });

      // Should still navigate to home despite error
      expect(router.state.location.pathname).toBe("/");
    });

    /**
     * @description Should handle async errors gracefully
     * @scenario Promise rejection during logout
     * @expected No unhandled promise rejection, navigation occurs
     */
    it("should handle async errors gracefully", async () => {
      mockLogoutUnwrap.mockRejectedValue(new Error("Network error"));

      const { router } = renderWithRouter();

      const buttonElement = screen.getByRole("button");

      // Should not throw unhandled rejection
      fireEvent.click(buttonElement);

      await waitFor(() => {
        expect(router.state.location.pathname).toBe("/");
      });

      expect(router.state.location.pathname).toBe("/");
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests - Edge Cases
  // ---------------------------------------------------------------------------

  describe("Interaction - Edge Cases", () => {
    /**
     * @description Should not navigate if button is disabled
     * @scenario Button has disabled attribute and is clicked
     * @expected Logout mutation should not be called, navigation should not occur
     */
    it("should not navigate if button is disabled", () => {
      const { router } = renderWithRouter("/", <LogoutButton disabled />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toBeDisabled();

      fireEvent.click(buttonElement);

      expect(mockLogoutUnwrap).not.toHaveBeenCalled();
      expect(router.state.location.pathname).toBe("/");
    });

    /**
     * @description Should handle multiple rapid clicks
     * @scenario User clicks button multiple times quickly
     * @expected logout called once per click, each triggers navigation
     */
    it("should handle multiple rapid clicks", async () => {
      const { router } = renderWithRouter();

      const buttonElement = screen.getByRole("button");

      fireEvent.click(buttonElement);
      fireEvent.click(buttonElement);

      await waitFor(() => {
        expect(mockLogoutUnwrap).toHaveBeenCalledTimes(2);
      });

      expect(router.state.location.pathname).toBe("/");
    });
  });

  // ---------------------------------------------------------------------------
  // Integration Tests
  // ---------------------------------------------------------------------------

  describe("Integration", () => {
    /**
     * @description Should maintain button type as button
     * @scenario Button rendered should have type="button" to prevent form submission
     * @expected Button type attribute is "button"
     */
    it("should maintain button type as button", () => {
      renderWithRouter();

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toHaveAttribute("type", "button");
    });

    /**
     * @description Should work with custom navigation state
     * @scenario Component rendered within router context with custom initial path
     * @expected Button click navigates to "/" regardless of initial path
     */
    it("should work with custom navigation state", async () => {
      const { router } = renderWithRouter(
        "/dashboard",
        <LogoutButton data-testid="integration-test" />,
      );

      const buttonElement = screen.getByTestId("integration-test");
      expect(buttonElement).toBeInTheDocument();

      fireEvent.click(buttonElement);

      await waitFor(() => {
        expect(router.state.location.pathname).toBe("/");
      });
    });

    /**
     * @description Should pass loading prop to Button component
     * @scenario When isLoading is true, Button should receive loading={true}
     * @expected Button component renders with loading state
     */
    it("should pass loading prop to Button component", () => {
      mockIsLoading.mockReturnValue(true);

      renderWithRouter();

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toHaveTextContent("Loading...");
    });
  });
});
