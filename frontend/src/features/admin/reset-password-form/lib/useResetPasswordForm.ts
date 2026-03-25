import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import { useState } from "react";

import { useResetPasswordMutation } from "@/entities/user";

import type { IResetPasswordFormProps } from "./types";

/**
 * Interface representing the state of validation errors in the reset password
 * form.
 */
export interface ErrorsStateType {
  new_password?: string;
  new_password_confirm?: string;
}

/**
 * Custom React Hook for handling the logic of a password reset form.
 *
 * Manages form state including new password, confirmation, validation errors,
 * and submission. Communicates with the backend via a mutation to reset
 * the user's password.
 */
export const useResetPasswordForm = ({
  userId,
  onSuccess,
}: IResetPasswordFormProps) => {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errors, setErrors] = useState<ErrorsStateType>({});

  const [resetPassword, { isLoading }] = useResetPasswordMutation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    if (newPassword !== confirmPassword) {
      setErrors({ new_password_confirm: "Пароли не совпадают" });
      return;
    }

    try {
      const result = await resetPassword({
        id: userId,
        newPassword: newPassword,
      }).unwrap();
      onSuccess?.(result.detail);
    } catch (err) {
      const error = err as FetchBaseQueryError;
      if (error.data && typeof error.data === "object") {
        const serverErrors = error.data as Record<string, string[]>;
        setErrors({
          new_password: serverErrors.newPassword?.[0],
          new_password_confirm: serverErrors.confirmPassword?.[0],
        });
      } else {
        setErrors({ new_password: "Не удалось сбросить пароль" });
      }
    }
  };

  return {
    newPassword,
    confirmPassword,
    errors,
    isLoading,
    setNewPassword,
    setConfirmPassword,
    handleSubmit,
  };
};
