/**
 * Represents the possible roles used for access control in the auth guard.
 */
export type AuthGuardRole = "guest" | "user" | "admin";

/**
 * Props interface for the AuthGuard component, which controls access
 * to protected routes based on user role.
 */
export interface IAuthGuardProps {
  children: React.ReactNode;
  accessLevel?: AuthGuardRole;
  redirectPath?: string;
}
