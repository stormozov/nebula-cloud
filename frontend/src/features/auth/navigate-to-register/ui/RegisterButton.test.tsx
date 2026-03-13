import { fireEvent, render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RegisterButton } from "./RegisterButton";

// ============================================================================
// MOCKS CONFIGURATION
// ============================================================================

// Mock for 'classnames' utility
vi.mock("classnames", () => ({
  default: vi.fn((...classes: (string | undefined)[]) =>
    classes.filter(Boolean).join(" "),
  ),
}));

// Mock for '@/shared/ui' Button component
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
 * @returns Render result from testing-library
 */
const renderWithRouter = (initialPath = "/") => {
  const router = createMemoryRouter(
    [
      {
        path: "*",
        element: <RegisterButton />,
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

describe("RegisterButton", () => {
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
     * @expected Button text is "Регистрация", variant is "primary", size is "medium"
     */
    it("should render with default props correctly", () => {
      renderWithRouter();

      const buttonElement = screen.getByRole("button");

      expect(buttonElement).toHaveTextContent("Регистрация");
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
            element: <RegisterButton variant="secondary" size="large" />,
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
     * @scenario Passing children="Create Account" should change button text
     * @expected Button text content matches provided children prop
     */
    it("should apply custom children text", () => {
      const customText = "Create Account";
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <RegisterButton>{customText}</RegisterButton>,
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
     * @scenario Passing className="custom-class" should be combined with "register-button"
     * @expected ClassList contains both "register-button" and "custom-class"
     */
    it("should merge custom className with base class", () => {
      const customClass = "custom-class";

      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <RegisterButton className={customClass} />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByRole("button");
      expect(buttonElement.className).toContain("register-button");
      expect(buttonElement.className).toContain(customClass);
    });

    /**
     * @description Should pass rest props to underlying Button
     * @scenario Passing data-testid="reg-btn" should be present on button
     * @expected Button element has data-testid attribute
     */
    it("should pass rest props to underlying Button", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <RegisterButton data-testid="reg-btn" />,
          },
        ],
        {
          initialEntries: ["/"],
        },
      );

      render(<RouterProvider router={router} />);

      const buttonElement = screen.getByTestId("reg-btn");
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
            element: <RegisterButton fullWidth />,
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
     * @description Should navigate to registration page on click
     * @scenario User clicks the button should trigger navigation hook
     * @expected useNavigate called with "/auth?tab=register" exactly once
     */
    it("should navigate to registration page on click", () => {
      const router = createMemoryRouter(
        [
          {
            path: "*",
            element: <RegisterButton />,
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
      expect(router.state.location.search).toBe("?tab=register");
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
            element: <RegisterButton disabled />,
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
            element: <RegisterButton />,
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
            element: <RegisterButton data-testid="integration-test" />,
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
  });
});
