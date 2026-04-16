import type { JSX } from "react";

import { Button, ControlledInput, Form } from "@/shared/ui";

import type { IUseLoginFormProps } from "../lib/types";
import { useLoginForm } from "../lib/useLoginForm";

/**
 * Login form component for user authentication.
 * Renders input fields for username and password with validation.
 *
 * @param {Object} props - Component props
 * @param {() => void} props.onSuccess - Callback on successful login (optional)
 * @param {(error: string) => void} props.onError - Callback on login error
 *  (optional)
 *
 * @returns {JSX.Element} Login form component
 *
 * @example
 * <LoginForm
 *   onSuccess={() => console.log('Logged in')}
 *   onError={(msg) => setGlobalError(msg)}
 * />
 */
export function LoginForm({
  onSuccess,
  onError,
}: IUseLoginFormProps): JSX.Element {
  const {
    formData,
    errors,
    isSubmitting,
    handleChange,
    handleBlur,
    handleSubmit,
  } = useLoginForm({ onSuccess, onError });

  return (
    <Form className="login-form" onSubmit={handleSubmit} noValidate>
      <ControlledInput
        value={formData.username}
        onChange={handleChange("username")}
        onBlur={handleBlur("username")}
        error={errors.username}
        label="Логин"
        placeholder="Введите логин"
        disabled={isSubmitting}
        required
        autoComplete="username"
      />

      <ControlledInput
        value={formData.password}
        onChange={handleChange("password")}
        onBlur={handleBlur("password")}
        error={errors.password}
        label="Пароль"
        placeholder="Введите пароль"
        type="password"
        disabled={isSubmitting}
        required
        autoComplete="current-password"
      />

      {errors.submit && <Form.SubmitErrorBlock errors={errors.submit} />}

      <Button
        type="submit"
        variant="primary"
        size="large"
        icon={{ name: "login" }}
        loading={isSubmitting}
        fullWidth
        className="login-form__submit-btn"
      >
        Войти
      </Button>
    </Form>
  );
}
