import { useEffect, useState } from "react";
import { toast } from "react-toastify";

import {
  type UserDetailsResponse,
  useUpdateUserMutation,
} from "@/entities/user";

/**
 * Interface defining the structure of form values in the edit user form.
 */
export interface IFormValues {
  email: string;
  firstName: string;
  lastName: string;
}

/**
 * Props interface for the useEditUserForm custom hook.
 */
export interface UseEditUserFormProps {
  user: UserDetailsResponse;
  onSuccess?: () => void;
  onCancel?: () => void;
}

/**
 * Custom hook for managing the edit user form state and logic.
 *
 * Handles form initialization, input changes, form submission, and API
 * interaction. Tracks which fields have been modified and only sends changed
 * fields to the API. Uses RTK Query's useUpdateUserMutation for updating user
 * data. Automatically updates form values when the user prop changes.
 *
 * @example
 * const { formValues, isLoading, handleChange, handleSubmit } = useEditUserForm({
 *   user: userData,
 *   onSuccess: handleSuccess,
 *   onCancel: handleCancel
 * });
 */
export const useEditUserForm = ({
  user,
  onSuccess,
  onCancel,
}: UseEditUserFormProps) => {
  const [formValues, setFormValues] = useState<IFormValues>({
    email: user.email || "",
    firstName: user.firstName || "",
    lastName: user.lastName,
  });

  const [updateUser, { isLoading }] = useUpdateUserMutation();

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setFormValues({
      firstName: user.firstName || "",
      lastName: user.lastName || "",
      email: user.email,
    });
  }, [user]);

  const handleChange = (field: string, value: string) => {
    setFormValues((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const changedFields: Record<string, string> = {};
    if (formValues.firstName !== (user.firstName || "")) {
      changedFields.first_name = formValues.firstName;
    }
    if (formValues.lastName !== (user.lastName || "")) {
      changedFields.last_name = formValues.lastName;
    }
    if (formValues.email !== user.email) {
      changedFields.email = formValues.email;
    }

    if (Object.keys(changedFields).length === 0) {
      onCancel?.(); // Nothing has changed — we`re closing it
      return;
    }

    try {
      await updateUser({ id: user.id, data: changedFields }).unwrap();
      onSuccess?.();
      toast.success(`Данные пользователя ${user.id} успешно обновлены`, {
        position: "top-center",
      });
    } catch (err) {
      console.error("Failed to update user:", err);
    }
  };

  return {
    formValues,
    isLoading,
    handleChange,
    handleSubmit,
  };
};
