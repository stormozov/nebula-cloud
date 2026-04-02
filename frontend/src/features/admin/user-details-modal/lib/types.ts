import type { ReactNode } from "react";
import type { UserDetailsResponse } from "@/entities/user";
import type { ModalConfirmDialogRequest } from "@/shared/ui";

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
   * Callback function to request a confirmation from the user.
   */
  requestConfirm: ModalConfirmDialogRequest;

  /**
   * Callback function to handle the success of an action.
   */
  onSuccess: (message?: string, close?: boolean) => void;

  /**
   * Callback function to close the entire user details modal.
   */
  onClose: () => void;
}

/**
 * Interface defining the structure of an information item in the modal.
 */
export interface IUserDetailsInfoItem {
  /** The title of the information item */
  title: string;

  /** Additional information or content associated with the item */
  value: ReactNode;

  /** The value to be copied to the clipboard */
  copyValue: string;

  /** The value of the information item */
  originalValue?: string;
}

/**
 * Props interface for the modal content component.
 */
export interface IModalContentProps {
  /** The ID of the user whose details are being displayed */
  userId: number;
  /** An array of user IDs */
  allUserIds: number[];
  /** Indicates if there are more users to load */
  hasPaginationMore: boolean;
  /** Callback to load more users */
  onLoadMore: () => void;
  /** Callback to navigate to a different user */
  onNavigate: (userId: number) => void;
  /** Request for a confirmation dialog */
  requestConfirm: ModalConfirmDialogRequest;
  /** Callback to close the modal */
  onClose: () => void;
  /** Indicates if the confirmation dialog is open */
  isConfirmOpen?: boolean;
}
