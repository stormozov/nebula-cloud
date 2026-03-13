import { fireEvent, render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LoginButton } from "./LoginButton";

// ============================================================================
// MOCKS CONFIGURATION
// ============================================================================

// Mock for 'classnames' utility
vi.mock("classnames", () => ({
  default: vi.fn((...classes: (string | undefined)[]) =>
    classes.filter(Boolean).join(" "),
  ),
}));

// Mock for '@/shared/ui' Button component with strict typing
vi.mock("@/shared/ui", () => ({
  Button: ({
    children,
    onClick,
    className,
    type,
    ...props
  }: {
    children: React.ReactNode;
    onClick?: () => void;
    className?: string;
    type?: "button" | "submit" | "reset";
    [key: string]: unknown;
  }) => (
    <button onClick={onClick} className={className} type={type} {...props}>
      {children}
    </button>
  ),
}));

// ============================================================================
// TEST HELPERS
// ============================================================================

/**
 * Helper to render component with Router context
 * @param initialPath - Initial path for the router
 * @param element - Optional custom element to render
 * @returns Render result from testing-library
 */
const renderWithRouter = (
  initialPath = "/",
  element: React.ReactElement = <LoginButton />,
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
  return render(<RouterProvider router={router} />);
};

// ============================================================================
// TEST SUITE
// ============================================================================

describe("LoginButton", () => {
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
     * @expected Button text is "Вход", variant is "primary", size is "medium"
     */
    it("should render with default props correctly", () => {
      renderWithRouter();

      const buttonElement = screen.getByRole("button");

      expect(buttonElement).toHaveTextContent("Вход");
      expect(buttonElement).toBeInTheDocument();
    });

    /**
     * @description Should apply custom variant and size props
     * @scenario Passing variant="secondary" and size="large" should propagate to Button
     * @expected Button component receives correct variant and size props
     */
    it("should apply custom variant and size props", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton variant="secondary" size="large" />,
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
     * @scenario Passing children="Sign In" should change button text
     * @expected Button text content matches provided children prop
     */
    it("should apply custom children text", () => {
      const customText = "Sign In";
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton>{customText}</LoginButton>,
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
     * @scenario Passing className="custom-class" should be combined with "login-button"
     * @expected ClassList contains both "login-button" and "custom-class"
     */
    it("should merge custom className with base class", () => {
      const customClass = "custom-class";

      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton className={customClass} />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement.className).toContain("login-button");
      expect(buttonElement.className).toContain(customClass);
    });

    /**
     * @description Should pass rest props to underlying Button
     * @scenario Passing data-testid="login-btn" should be present on button
     * @expected Button element has data-testid attribute
     */
    it("should pass rest props to underlying Button", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton data-testid="login-btn" />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByTestId("login-btn");
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
            element: <LoginButton fullWidth />,
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

  // -------------------------------------------------------------------------
  // Interaction Tests
  // -------------------------------------------------------------------------

  describe("Interaction", () => {
    /**
     * @description Should navigate to login page on click
     * @scenario User clicks the button should trigger navigation hook
     * @expected useNavigate called with "/auth" exactly once
     */
    it("should navigate to login page on click", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      fireEvent.click(buttonElement);

      expect(router.state.location.pathname).toBe("/auth");
      expect(router.state.location.search).toBe("");
    });

    /**
     * @description Should not navigate if button is disabled
     * @scenario Button has disabled attribute and is clicked
     * @expected Navigation should not occur
     */
    it("should not navigate if button is disabled", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton disabled />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement).toBeDisabled();

      const initialPathname = router.state.location.pathname;
      fireEvent.click(buttonElement);

      expect(router.state.location.pathname).toBe(initialPathname);
    });

    /**
     * @description Should handle multiple clicks correctly
     * @scenario User clicks the button multiple times
     * @expected Navigation triggers on each click
     */
    it("should handle multiple clicks correctly", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");

      fireEvent.click(buttonElement);
      expect(router.state.location.pathname).toBe("/auth");

      fireEvent.click(buttonElement);
      expect(router.state.location.pathname).toBe("/auth");
    });
  });

  // -------------------------------------------------------------------------
  // Integration Tests
  // -------------------------------------------------------------------------

  describe("Integration", () => {
    /**
     * @description Should work with custom navigation state
     * @scenario Component rendered within router context with state
     * @expected Button click preserves router functionality
     */
    it("should work with custom navigation state", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton data-testid="integration-test" />,
          },
        ],
        {
          initialEntries: ["/test-path"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByTestId("integration-test");
      expect(buttonElement).toBeInTheDocument();

      fireEvent.click(buttonElement);
      expect(router.state.location.pathname).toBe("/auth");
    });

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
     * @description Should navigate to auth without query params
     * @scenario Clicking button should navigate to /auth without additional parameters
     * @expected Location pathname is "/auth" and search is empty
     */
    it("should navigate to auth without query params", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <LoginButton />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      fireEvent.click(buttonElement);

      expect(router.state.location.pathname).toBe("/auth");
      expect(router.state.location.search).toBe("");
      expect(router.state.location.hash).toBe("");
    });
  });
});
