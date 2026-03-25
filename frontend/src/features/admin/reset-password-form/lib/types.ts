/**
 * Props interface for the ResetPasswordForm component.
 */
export interface IResetPasswordFormProps {
  userId: number;
  onSuccess?: (message: string) => void;
  onCancel?: () => void;
}
