import type { UserDetailsResponse } from "@/entities/user";

/**
 * Union type that defines the possible actions available
 * in the UserDetailsModal component.
 *
 * @remarks
 * This type is used to control which action buttons or functionality should be
 * displayed in the user details modal.
 */
export type UserDetailsModalActionsType = "edit" | "reset-password" | "none";

/**
 * Interface defining the props required for the user actions functionality.
 *
 * Contains all necessary data and handlers for managing user interaction with
 * the modal.
 */
export interface IUserDetailsModalActionsProps {
  /**
   * The user object containing detailed information about the current user.
   *
   * This data is displayed in the modal and can be edited in the form.
   */
  user: UserDetailsResponse;

  /**
   * The current action state of the modal, determining which view
   * or functionality is active.
   */
  action: UserDetailsModalActionsType;

  /**
   * Boolean indicating whether the current user is the same as the user being
   * displayed in the modal.
   */
  isCurrentUser: boolean;

  /**
   * Function to update the current action state of the modal.
   *
   * Used to switch between different modes (e.g., "edit" or "none").
   *
   * @param action - The new action state to set
   */
  setAction: (action: UserDetailsModalActionsType) => void;

  /**
   * Callback function to close the entire user details modal.
   */
  onClose: () => void;

  /**
   * Callback function to handle successful form submission.
   */
  editFormSuccess: () => void;

  /**
   * Callback function to handle successful password reset.
   */
  resetPasswordFormSuccess: (message: string) => void;

  /**
   * Callback function to handle successful toggle of user activity.
   */
  toggleActiveSuccess: () => void;

  /**
   * Callback function to handle successful toggle of user admin status.
   */
  toggleAdminSuccess: () => void;

  /**
   * Callback function to handle successful deletion of the user.
   */
  deleteUserSuccess: (message: string) => void;
}
