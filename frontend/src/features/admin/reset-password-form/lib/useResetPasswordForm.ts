import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import { useState } from "react";

import { useResetPasswordMutation } from "@/entities/user";

import type {
  IErrorsState,
  IResetPasswordFormProps,
  IUseResetPasswordFormReturns,
} from "./types";

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
}: IResetPasswordFormProps): IUseResetPasswordFormReturns => {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errors, setErrors] = useState<IErrorsState>({});

  const [resetPassword, { isLoading }] = useResetPasswordMutation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    if (newPassword !== confirmPassword) {
      setErrors({ newPasswordConfirm: "Пароли не совпадают" });
      return;
    }

    try {
      const newData = { id: userId, newPassword: newPassword };
      const response = await resetPassword(newData).unwrap();
      onSuccess?.(response.detail);
    } catch (err) {
      const error = err as FetchBaseQueryError;
      if (error.data && typeof error.data === "object") {
        const serverErrors = error.data as Record<string, string[]>;
        setErrors({
          newPassword: serverErrors.newPassword?.[0],
          newPasswordConfirm: serverErrors.confirmPassword?.[0],
        });
      } else {
        setErrors({ newPassword: "Не удалось сбросить пароль" });
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
