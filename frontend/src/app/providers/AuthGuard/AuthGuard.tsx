import { Navigate, useLocation } from "react-router";

import { useAppSelector } from "@/app/store/hooks";
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
}: IAuthGuardProps) => {
  const location = useLocation();

  const isAuthenticated = useAppSelector(selectIsAuthenticated);
  const isStaff = useAppSelector(selectIsStaff);
  const isLoading = useAppSelector(selectIsLoading);

  if (isLoading) return null;

  if (accessLevel === "guest" && isAuthenticated) {
    return (
      <Navigate
        to={redirectPath ?? (isStaff ? "/admin/dashboard" : "/disk")}
        replace
      />
    );
  }

  if (accessLevel !== "guest" && !isAuthenticated) {
    return <Navigate to={redirectPath ?? "/auth"} replace />;
  }

  if (accessLevel === "admin" && !isStaff) {
    return <Navigate to={redirectPath ?? "/disk"} replace />;
  }

  if (accessLevel === "user" && isAuthenticated && location.pathname === "/") {
    return <Navigate to="/disk" replace />;
  }

  return <>{children}</>;
};
