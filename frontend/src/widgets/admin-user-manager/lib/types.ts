import type { IUserListResponse } from "@/entities/user";
import type {
  IListStates,
  IListStatesRenders,
  ModalConfirmDialogRequest,
} from "@/shared/ui";

/**
 * Represents the selected user ID, which can be a number or null if no user
 * is selected.
 */
export type SelectUser = number | null;

/**
 * A function type that sets the selected user ID.
 *
 * @param userId - The user ID to select, or null to deselect.
 */
type SetSelectedUserIdFunc = (userId: SelectUser) => void;

/**
 * Interface representing the data structure returned by the user manager list.
 */
export interface IUserManagerListData {
  /** Array of user list response objects. */
  items: IUserListResponse[];
  /** Array of all user IDs present in the items array. */
  allIds: number[];
  /** Total count of users available in the list. */
  totalCount: number;
  /** Indicates whether more users are available for loading. */
  hasMore: boolean;
  /**
   * Optional object containing the current states of list items
   * (e.g., loading, error states).
   */
  states?: IListStates;
  /** Optional object containing render-specific state info for list. */
  renders?: IListStatesRenders;
}

/**
 * Interface representing the return value of a custom hook managing selected
 * user state.
 */
export interface IUseUserManagerSelected {
  /** The currently selected user ID, or null if no user is selected. */
  userId: SelectUser;
  /** Function to update the selected user ID. */
  setUserId: SetSelectedUserIdFunc;
}

/**
 * Interface representing the return value of a custom hook managing pagination
 * in the user manager.
 */
export interface IUseUserManagerPagination {
  /** Indicates whether the "load more" operation is currently in progress. */
  isLoadMoreLoading: boolean;
  /**
   * Function to load additional users, typically used for infinite scroll
   * or pagination.
   *
   * @param shouldAutoNavigate - If true, the UI should automatically navigate
   * to the newly loaded content.
   */
  loadMore: (shouldAutoNavigate: boolean) => void;
}

/**
 * Interface representing the return value of a custom hook managing search
 * functionality in the user manager.
 */
export interface IUseUserManagerSearch {
  /** The current search term entered by the user. */
  term: string;
  /** The debounced version of the search term. */
  debouncedTerm: string;
  /**
   * Function to directly update the search term.
   *
   * @param term - The new search term to set.
   */
  setTerm: (term: string) => void;
  /**
   * Handler function to be called when the search input value changes.
   * Typically used as an event handler in input elements.
   *
   * @param value - The new value from the search input.
   */
  onSearchChange: (value: string) => void;
}

/**
 * Interface representing the return value of a custom hook managing
 * a confirmation modal in the user manager.
 */
export interface IUseUserManagerConfirmModal {
  /** Indicates whether the confirmation modal is currently open. */
  isOpen: boolean;
  /** The title displayed in the confirmation modal. */
  title: string;
  /** The message or description displayed in the body of the confirm modal. */
  message: string;
  /**
   * The request object that triggered the confirmation dialog, containing
   * context about the action to confirm.
   */
  requestConfirm: ModalConfirmDialogRequest;
  /** Callback function executed when the user confirms the action. */
  handleConfirm: () => void;
  /** Callback function executed when the user cancels the action. */
  handleCancel: () => void;
}

/**
 * Interface representing the return value of a custom hook managing the user
 * details modal in the user manager.
 */
export interface IUseUserManagerDetailsModal {
  /** The ID of the currently displayed user in the details modal. */
  userId: SelectUser;
  /** Array of all available user IDs, used for nav between users in the modal. */
  allUserIds: number[];
  /** Indicates whether more users can be loaded. */
  hasPaginationMore: boolean;
  /** Indicates whether the confirm modal is open from within the details modal. */
  isConfirmOpen: boolean;
  /** Callback to load more users. */
  onLoadMore: () => void;
  /** Function to navigate to a different user by their ID. */
  onNavigate: SetSelectedUserIdFunc;
  /**
   * The current confirmation request object, passed to the confirm modal
   * for handling user actions.
   */
  requestConfirm: ModalConfirmDialogRequest;
  /** Callback function to close the user details modal. */
  onClose: () => void;
  /**
   * Callback function triggered when a user is deleted.
   * Used to update the UI or state accordingly after deletion.
   */
  onUserDeleted: (userId: number) => void;
}

/**
 * Interface representing the complete return value of the `useUserManager` hook.
 *
 * Combines all sub-hooks and state managers into a single contract for the user
 * management feature.
 */
export interface IUseUserManagerReturns {
  /** Contains the list data of users. */
  usersList: IUserManagerListData;
  /** Manages the currently selected user ID and provides a setter function. */
  selected: IUseUserManagerSelected;
  /**
   * Handles pagination logic such as loading more users and tracking loading
   * state.
   */
  pagination: IUseUserManagerPagination;
  /**
   * Manages search functionality including input term, debounced term,
   * and change handlers.
   */
  search: IUseUserManagerSearch;
  /**
   * Controls the behavior and state of the confirmation modal.
   */
  confirmModal: IUseUserManagerConfirmModal;
  /**
   * Controls the behavior and state of the user details modal,
   * including navigation and deletion.
   */
  userDetailsModal: IUseUserManagerDetailsModal;
}
