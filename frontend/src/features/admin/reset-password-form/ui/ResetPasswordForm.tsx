import { Button, ControlledInput, Heading, PageWrapper, Icon } from "@/shared/ui";

import type { IResetPasswordFormProps } from "../lib/types";
import { useResetPasswordForm } from "../lib/useResetPasswordForm";

import "./ResetPasswordForm.scss";

/**
 * A React component that renders a form for resetting a user's password.
 *
 * The form includes fields for entering and confirming a new password,
 * client-side and server-side validation, loading state during submission,
 * and buttons to submit or cancel the operation.
 *
 * It uses the `useResetPasswordForm` custom hook to manage form state and logic.
 *
 * @example
 * <ResetPasswordForm
 *   userId={123}
 *   onSuccess={(msg) => alert(msg)}
 *   onCancel={() => history.back()}
 * />
 */
export function ResetPasswordForm({
  userId,
  onSuccess,
  onCancel,
}: IResetPasswordFormProps) {
  const {
    newPassword,
    confirmPassword,
    errors,
    isLoading,
    setNewPassword,
    setConfirmPassword,
    handleSubmit,
  } = useResetPasswordForm({
    userId,
    onSuccess,
  });

  return (
    <form onSubmit={handleSubmit} className="reset-password-form">
      <Heading level={4}>Сбросить пароль</Heading>

      <PageWrapper className="reset-password-form__inputs">
        <ControlledInput
          label="Новый пароль"
          type="password"
          value={newPassword}
          onChange={setNewPassword}
          error={errors.newPassword}
          required
        />
        <ControlledInput
          label="Подтверждение пароля"
          type="password"
          value={confirmPassword}
          onChange={setConfirmPassword}
          error={errors.newPasswordConfirm}
          required
        />
      </PageWrapper>

      <PageWrapper className="edit-user-form__buttons" justify="end">
        <Button variant="secondary" onClick={onCancel}>
          <Icon name="close" />
          Отмена
        </Button>
        <Button type="submit" loading={isLoading}>
          <Icon name="save" />
          Сохранить
        </Button>
      </PageWrapper>
    </form>
  );
}
