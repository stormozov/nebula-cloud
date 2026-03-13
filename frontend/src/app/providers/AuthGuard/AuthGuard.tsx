import { type JSX, useEffect } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router";

import {
  selectIsAuthenticated,
  selectIsLoading,
  selectIsStaff,
} from "@/entities/user";

import type { IAuthGuardProps } from "./types";

/**
 * Protected route wrapper with role-based access control.
 *
 * Handles redirects based on authentication status and user role.
 *
 * @param {IAuthGuardProps} props - Component props
 * @param {React.ReactNode} props.children - Child components to render
 *  if access is granted
 * @param {AuthGuardRole} props.accessLevel - Required role for access
 * @param {string} props.redirectPath - Custom redirect path (optional)
 *
 * @returns {JSX.Element} Children component or null during redirect
 *
 * @example
 * // Public route (auth page)
 * { path: '/auth', element: <AuthGuard role="guest"><PageAuth /></AuthGuard> }
 *
 * // Protected route (disk)
 * { path: '/disk', element: <AuthGuard role="user"><PageClientDisk /></AuthGuard> }
 *
 * // Admin-only route
 * { path: '/admin', element: <AuthGuard role="admin"><PageAdmin /></AuthGuard> }
 */
export const AuthGuard = ({
  children,
  accessLevel = "user",
  redirectPath,
}: IAuthGuardProps): JSX.Element | null => {
  const navigate = useNavigate();

  const isAuthenticated = useSelector(selectIsAuthenticated);
  const isStaff = useSelector(selectIsStaff);
  const isLoading = useSelector(selectIsLoading);

  useEffect(() => {
    // Skip redirect while loading auth state (initial app load)
    if (isLoading) return;

    // Logic for guest-only routes (e.g., /auth, /welcome for non-auth)
    if (accessLevel === "guest") {
      if (isAuthenticated) {
        // Authenticated users should not access guest routes
        navigate(redirectPath ?? "/disk", { replace: true });
      }
      return;
    }

    // Logic for authenticated routes
    if (!isAuthenticated) {
      // Not authenticated → redirect to auth page
      navigate(redirectPath ?? "/auth", { replace: true });
      return;
    }

    // Admin-only routes
    if (accessLevel === "admin" && !isStaff) {
      // Non-admin users trying to access admin routes
      navigate(redirectPath ?? "/disk", { replace: true });
      return;
    }

    // Welcome page for authenticated users → redirect to disk
    if (
      accessLevel === "user" &&
      isAuthenticated &&
      window.location.pathname === "/"
    ) {
      navigate("/disk", { replace: true });
      return;
    }
  }, [
    isAuthenticated,
    isStaff,
    isLoading,
    accessLevel,
    navigate,
    redirectPath,
  ]);

  // Show nothing during redirect or loading
  if (isLoading) return null;

  // Render children if access is granted
  return <>{children}</>;
};
