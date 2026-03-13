import { configureStore } from "@reduxjs/toolkit";
import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { Provider } from "react-redux";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { userSlice } from "@/entities/user/model/slice";
import type { IAuthState, IUser } from "@/entities/user/model/types";

import { AuthGuard } from "./AuthGuard";
import type { AuthGuardRole } from "./types";

// Mock navigate
const mockNavigate = vi.fn();

/**
 * Mock react-router
 */
vi.mock("react-router", async () => {
  const actual = await vi.importActual("react-router");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

/**
 * Creates a test store with customizable initial state.
 */
const createTestStore = (initialState: Partial<IAuthState> = {}) => {
  return configureStore({
    reducer: {
      user: userSlice.reducer,
    },
    preloadedState: {
      user: {
        user: null,
        accessToken: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        ...initialState,
      },
    } as { user: IAuthState },
  });
};

/**
 * Mock child component to verify access is granted.
 */
const MockChild = () => (
  <div data-testid="child-content">Protected Content</div>
);

/**
 * Test wrapper component with navigation tracking.
 */
const TestWrapper = ({
  children,
  initialEntries,
}: {
  children: ReactNode;
  initialEntries?: string[];
}) => {
  return (
    <MemoryRouter initialEntries={initialEntries ?? ["/"]}>
      {children}
    </MemoryRouter>
  );
};

/**
 * Renders AuthGuard with given props and returns useful utilities.
 */
const renderAuthGuard = ({
  accessLevel = "user",
  redirectPath,
  isAuthenticated = false,
  isStaff = false,
  isLoading = false,
  initialPath = "/disk",
}: {
  accessLevel?: AuthGuardRole;
  redirectPath?: string;
  isAuthenticated?: boolean;
  isStaff?: boolean;
  isLoading?: boolean;
  initialPath?: string;
} = {}) => {
  const user: IUser | null = isAuthenticated
    ? {
        id: 1,
        username: "testuser",
        email: "test@example.com",
        firstName: "Test",
        lastName: "User",
        isStaff,
      }
    : null;

  const store = createTestStore({
    isAuthenticated,
    isLoading,
    user,
  });

  const renderResult = render(
    <Provider store={store}>
      <TestWrapper initialEntries={[initialPath]}>
        <AuthGuard accessLevel={accessLevel} redirectPath={redirectPath}>
          <MockChild />
        </AuthGuard>
      </TestWrapper>
    </Provider>,
  );

  return {
    ...renderResult,
    store,
  };
};

describe("AuthGuard Component", () => {
  beforeEach(() => {
    // Clear mock before each test
    mockNavigate.mockClear();

    // Mock window.location
    vi.stubGlobal("location", {
      pathname: "/",
      href: "http://localhost/",
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  describe("Unauthenticated User Scenarios", () => {
    /**
     * @description Should redirect unauthenticated user from protected route to /auth
     * @scenario User is not authenticated and tries to access /disk
     * @expected Should redirect to /auth
     */
    it("should redirect unauthenticated user from /disk to /auth", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: false,
        accessLevel: "user",
        initialPath: "/disk",
      });

      // Wait for navigate to be called
      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/auth", { replace: true });
      });

      unmount();
    });

    /**
     * @description Should redirect unauthenticated user from admin route to /auth
     * @scenario User is not authenticated and tries to access /admin
     * @expected Should redirect to /auth
     */
    it("should redirect unauthenticated user from /admin to /auth", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: false,
        accessLevel: "admin",
        initialPath: "/admin",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/auth", { replace: true });
      });

      unmount();
    });

    /**
     * @description Should use custom redirect path when provided
     * @scenario Unauthenticated user with custom redirectPath
     * @expected Should redirect to custom path instead of default
     */
    it("should use custom redirect path when provided for unauthenticated user", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: false,
        accessLevel: "user",
        redirectPath: "/custom-login",
        initialPath: "/disk",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/custom-login", {
          replace: true,
        });
      });

      unmount();
    });
  });

  describe("Authenticated Non-Admin User Scenarios", () => {
    /**
     * @description Should redirect authenticated non-admin user from admin route to /disk
     * @scenario User is authenticated but not staff/admin, tries to access /admin
     * @expected Should redirect to /disk
     */
    it("should redirect authenticated non-admin user from /admin to /disk", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: false,
        accessLevel: "admin",
        initialPath: "/admin",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/disk", { replace: true });
      });

      unmount();
    });

    /**
     * @description Should use custom redirect path for non-admin user
     * @scenario Authenticated non-admin with custom redirectPath
     * @expected Should redirect to custom path
     */
    it("should use custom redirect path for non-admin user", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: false,
        accessLevel: "admin",
        redirectPath: "/custom-redirect",
        initialPath: "/admin",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/custom-redirect", {
          replace: true,
        });
      });

      unmount();
    });
  });

  describe("Authenticated Admin User Scenarios", () => {
    /**
     * @description Should allow authenticated admin user to access admin route
     * @scenario User is authenticated and is staff/admin, tries to access /admin
     * @expected Should render children (access granted)
     */
    it("should allow authenticated admin user to access /admin", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: true,
        accessLevel: "admin",
        initialPath: "/admin",
      });

      await waitFor(() => {
        expect(screen.getByTestId("child-content")).toBeInTheDocument();
      });

      // Should NOT have redirected
      expect(mockNavigate).not.toHaveBeenCalled();

      unmount();
    });

    /**
     * @description Should render children for authenticated admin user
     * @scenario Authenticated admin accesses admin page
     * @expected Protected content should be visible
     */
    it("should render children for authenticated admin user", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: true,
        accessLevel: "admin",
        initialPath: "/admin",
      });

      await waitFor(() => {
        expect(screen.getByText("Protected Content")).toBeInTheDocument();
      });

      unmount();
    });
  });

  describe("Guest Route Scenarios (Auth Page)", () => {
    /**
     * @description Should redirect authenticated user from /auth to /disk
     * @scenario Authenticated user tries to access auth page
     * @expected Should redirect to /disk
     */
    it("should redirect authenticated user from /auth to /disk", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        accessLevel: "guest",
        initialPath: "/auth",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/disk", { replace: true });
      });

      unmount();
    });

    /**
     * @description Should redirect authenticated user from auth page to custom path
     * @scenario Authenticated user with custom redirectPath accesses guest route
     * @expected Should redirect to custom path
     */
    it("should redirect authenticated user to custom path from guest route", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        accessLevel: "guest",
        redirectPath: "/custom-auth-redirect",
        initialPath: "/auth",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/custom-auth-redirect", {
          replace: true,
        });
      });

      unmount();
    });
  });

  describe("Loading State Scenarios", () => {
    /**
     * @description Should not render children while auth is loading
     * @scenario User state is loading (initial app load)
     * @expected Should return null, children not rendered
     */
    it("should not render children while auth is loading", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: false,
        isLoading: true,
        accessLevel: "user",
        initialPath: "/disk",
      });

      // While loading, should return null
      expect(screen.queryByTestId("child-content")).not.toBeInTheDocument();

      // Should NOT have redirected yet
      expect(mockNavigate).not.toHaveBeenCalled();

      unmount();
    });

    /**
     * @description Should render children after loading completes with valid auth
     * @scenario Loading completes and user is authenticated with proper access
     * @expected Should render children
     */
    it("should render children after loading with valid auth", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: true,
        isLoading: false,
        accessLevel: "admin",
        initialPath: "/admin",
      });

      await waitFor(() => {
        expect(screen.getByTestId("child-content")).toBeInTheDocument();
      });

      // Should NOT have redirected
      expect(mockNavigate).not.toHaveBeenCalled();

      unmount();
    });
  });

  describe("Welcome Page Redirect Scenarios", () => {
    /**
     * @description Should redirect authenticated user from root path to /disk
     * @scenario Authenticated user accesses root path "/"
     * @expected Should redirect to /disk
     */
    it("should redirect authenticated user from root to /disk", async () => {
      vi.stubGlobal("location", {
        pathname: "/",
        href: "http://localhost/",
      });

      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        accessLevel: "user",
        initialPath: "/",
      });

      await waitFor(
        () => {
          expect(mockNavigate).toHaveBeenCalledWith("/disk", { replace: true });
        },
        { timeout: 1000 },
      );

      unmount();
    });

    /**
     * @description Should not redirect authenticated user when not on root path
     * @scenario Authenticated user accesses a non-root path like /disk
     * @expected Should render children without redirect
     */
    it("should not redirect authenticated user when not on root path", async () => {
      vi.stubGlobal("location", {
        pathname: "/disk",
        href: "http://localhost/disk",
      });

      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        accessLevel: "user",
        initialPath: "/disk",
      });

      await waitFor(() => {
        expect(screen.getByTestId("child-content")).toBeInTheDocument();
      });

      // Should NOT have redirected
      expect(mockNavigate).not.toHaveBeenCalled();

      unmount();
    });
  });

  describe("Default Props and Edge Cases", () => {
    /**
     * @description Should use default accessLevel of "user"
     * @scenario No accessLevel prop provided
     * @expected Should default to "user" access level
     */
    it("should use default accessLevel of user when not provided", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: false,
        // accessLevel defaults to "user"
        initialPath: "/disk",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/auth", { replace: true });
      });

      unmount();
    });

    /**
     * @description Should render children for user access level when authenticated
     * @scenario Authenticated user accesses user-protected route
     * @expected Should render children
     */
    it("should render children for authenticated user with user access level", async () => {
      vi.stubGlobal("location", {
        pathname: "/disk",
        href: "http://localhost/disk",
      });

      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: false,
        accessLevel: "user",
        initialPath: "/disk",
      });

      await waitFor(() => {
        expect(screen.getByTestId("child-content")).toBeInTheDocument();
      });

      // Should NOT have redirected
      expect(mockNavigate).not.toHaveBeenCalled();

      unmount();
    });

    /**
     * @description Should allow authenticated non-admin user to access user route
     * @scenario Regular authenticated user accesses /disk
     * @expected Should render children
     */
    it("should allow authenticated non-admin user to access /disk", async () => {
      vi.stubGlobal("location", {
        pathname: "/disk",
        href: "http://localhost/disk",
      });

      const { unmount } = renderAuthGuard({
        isAuthenticated: true,
        isStaff: false,
        accessLevel: "user",
        initialPath: "/disk",
      });

      await waitFor(() => {
        expect(screen.getByTestId("child-content")).toBeInTheDocument();
      });

      // Should NOT have redirected
      expect(mockNavigate).not.toHaveBeenCalled();

      unmount();
    });
  });

  describe("Navigation Behavior", () => {
    /**
     * @description Should use replace option for navigation
     * @scenario Redirecting user to auth page
     * @expected Should use replace: true to avoid history stack pollution
     */
    it("should use replace option for navigation", async () => {
      const { unmount } = renderAuthGuard({
        isAuthenticated: false,
        accessLevel: "user",
        initialPath: "/disk",
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith("/auth", { replace: true });
      });

      unmount();
    });
  });

  describe("AuthGuard Export Verification", () => {
    /**
     * @description Should export AuthGuard component
     * @scenario Importing AuthGuard
     * @expected Should be a function component
     */
    it("should export AuthGuard as a function component", async () => {
      expect(AuthGuard).toBeDefined();
      expect(typeof AuthGuard).toBe("function");
    });
  });
});
