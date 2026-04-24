import type { JSX } from "react";

import { Button, ControlledInput, Form } from "@/shared/ui";

import { useRegisterForm } from "../lib/useRegisterForm";

/**
 * Registration form component for new user account creation.
 * Renders input fields for all required registration data with validation.
 *
 * @param {Object} props - Component props
 * @param {() => void} props.onSuccess - Callback on successful registration
 *  (optional)
 * @param {(error: string) => void} props.onError - Callback on registration
 *  error (optional)
 *
 * @returns {JSX.Element} Registration form component
 *
 * @example
 * <RegisterForm
 *   onSuccess={() => console.log('Registered')}
 *   onError={(msg) => setGlobalError(msg)}
 * />
 */
export function RegisterForm({
  onSuccess,
  onError,
}: {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}): JSX.Element {
  const {
    formData,
    errors,
    isSubmitting,
    handleChange,
    handleBlur,
    handleSubmit,
  } = useRegisterForm({ onSuccess, onError });

  return (
    <Form className="register-form" onSubmit={handleSubmit} noValidate>
      <Form.Row className="register-form__row register-form__row--double">
        <ControlledInput
          value={formData.firstName}
          onChange={handleChange("firstName")}
          onBlur={handleBlur("firstName")}
          error={errors.firstName}
          label="Имя"
          placeholder="Введите имя"
          disabled={isSubmitting}
          required
          autoComplete="given-name"
        />

        <ControlledInput
          value={formData.lastName}
          onChange={handleChange("lastName")}
          onBlur={handleBlur("lastName")}
          error={errors.lastName}
          label="Фамилия"
          placeholder="Введите фамилию"
          disabled={isSubmitting}
          required
          autoComplete="family-name"
        />
      </Form.Row>

      <ControlledInput
        value={formData.username}
        onChange={handleChange("username")}
        onBlur={handleBlur("username")}
        error={errors.username}
        label="Логин"
        placeholder="Придумайте логин"
        disabled={isSubmitting}
        required
        autoComplete="username"
      />

      <ControlledInput
        value={formData.email}
        onChange={handleChange("email")}
        onBlur={handleBlur("email")}
        error={errors.email}
        label="Email"
        placeholder="Введите email"
        type="email"
        disabled={isSubmitting}
        required
        autoComplete="email"
      />

      <ControlledInput
        value={formData.password}
        onChange={handleChange("password")}
        onBlur={handleBlur("password")}
        error={errors.password}
        label="Пароль"
        placeholder="Придумайте пароль"
        type="password"
        disabled={isSubmitting}
        required
        autoComplete="new-password"
      />

      <ControlledInput
        value={formData.passwordConfirm}
        onChange={handleChange("passwordConfirm")}
        onBlur={handleBlur("passwordConfirm")}
        error={errors.passwordConfirm}
        label="Подтверждение пароля"
        placeholder="Повторите пароль"
        type="password"
        disabled={isSubmitting}
        required
        autoComplete="new-password"
      />

      {errors.submit && <Form.SubmitErrorBlock errors={errors.submit} />}

      <Button
        type="submit"
        variant="primary"
        size="large"
        icon={{ name: "register" }}
        loading={isSubmitting}
        fullWidth
        className="register-form__submit-btn"
      >
        Зарегистрироваться
      </Button>
    </Form>
  );
}
