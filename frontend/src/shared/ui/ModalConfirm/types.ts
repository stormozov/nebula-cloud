/**
 * Interface describing the state of a confirmation modal dialog.
 */
export interface IModalConfirmState {
  /** Flag indicating whether the modal is currently open or closed. */
  isOpen: boolean;
  /** The title of the confirmation modal. */
  title: string;
  /** The main message or description shown in the body of the modal. */
  message: string;
  /** Callback function to execute when the user confirms the action. */
  onConfirm: () => Promise<void>;
}

/**
 * Type definition for a function that requests the display of a confirmation
 * dialog.
 */
export type ModalConfirmDialogRequest = (
  /** The title to display in the confirmation modal. */
  title: string,
  /**
   * The descriptive message shown to the user explaining the consequence
   * of the action.
   */
  message: string,
  /** The callback function to invoke when the user confirms the action. */
  onConfirm: () => Promise<void>,
) => void;

/**
 * Interface defining the return values from the useModalConfirm hook.
 */
export interface IUseModalConfirmReturns {
  /** The current state of the confirmation modal dialog. */
  dialog: IModalConfirmState;
  /** Function to request the display of a confirmation dialog. */
  requestConfirm: ModalConfirmDialogRequest;
  /** Function to handle the confirmation action. */
  handleConfirm: () => Promise<void>;
  /** Function to handle the cancellation action. */
  handleCancel: () => void;
}
