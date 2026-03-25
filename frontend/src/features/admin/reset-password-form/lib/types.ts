/**
 * Props interface for the ResetPasswordForm component.
 */
export interface IResetPasswordFormProps {
  userId: number;
  onSuccess?: (message: string) => void;
  onCancel?: () => void;
}

/**
 * Interface representing the state of validation errors in the reset password
 * form.
 */
export interface IErrorsState {
  newPassword?: string;
  newPasswordConfirm?: string;
}

/**
 * Interface describing the return value of the useResetPasswordForm
 * custom hook.
 */
export interface IUseResetPasswordFormReturns {
  /** Current validation errors in the form. */
  errors: IErrorsState;
  /** The current value of the new password input field. */
  newPassword: string;
  /** The current value of the confirm password input field. */
  confirmPassword: string;
  /** Flag indicating whether the form is currently submitting. */
  isLoading: boolean;
  /** React state setter function to update the `newPassword` value. */
  setNewPassword: React.Dispatch<React.SetStateAction<string>>;
  /** React state setter function to update the `confirmPassword` value. */
  setConfirmPassword: React.Dispatch<React.SetStateAction<string>>;
  /** Form submission handler. */
  handleSubmit: (e: React.FormEvent) => Promise<void>;
}
