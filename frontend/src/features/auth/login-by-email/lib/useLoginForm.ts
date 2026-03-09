import { useCallback, useState } from "react";
import { useNavigate } from "react-router";

import { useLoginMutation } from "@/entities/user";
import type { IValidationResult } from "@/shared/types/validation";
import { validateLogin, validatePassword } from "@/shared/validators";

import type {
  ILoginFormErrors,
  ILoginFormValues,
  IUseLoginFormProps,
  IUseLoginFormReturn,
} from "./types";

/**
 * Initial form state for useLoginForm hook.
 */
const FORM_DATA_INIT_STATE: ILoginFormValues = {
  username: "",
  password: "",
};

/**
 * Custom hook for login form logic.
 * Handles validation, submission, and error management.
 *
 * @param {Object} options - Hook options
 * @param {() => void} options.onSuccess - Callback on successful login
 * @param {(error: string) => void} options.onError - Callback on login error
 *
 * @returns {IUseLoginFormReturn} Form state and handlers
 *
 * @example
 * const {
 *   formData, errors, isSubmitting, handleChange, handleSubmit
 * } = useLoginForm({
 *   onSuccess: () => navigate('/disk'),
 *   onError: (msg) => setSubmitError(msg),
 * });
 */
export const useLoginForm = ({
  onSuccess,
  onError,
}: IUseLoginFormProps): IUseLoginFormReturn => {
  const navigate = useNavigate();
  const [login, { isLoading }] = useLoginMutation();

  const [formData, setFormData] =
    useState<ILoginFormValues>(FORM_DATA_INIT_STATE);

  const [errors, setErrors] = useState<ILoginFormErrors>({});

  /**
   * Handle field value change.
   */
  const handleChange = useCallback(
    (field: keyof ILoginFormValues) =>
      (value: string): void => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        // Clear error for this field on change
        if (errors[field]) {
          setErrors((prev) => ({ ...prev, [field]: undefined }));
        }
      },
    [errors],
  );

  /**
   * Validate field on blur.
   */
  const handleBlur = useCallback(
    (field: keyof ILoginFormValues) => (): void => {
      let result: IValidationResult | null = null;

      if (field === "username") {
        result = validateLogin(formData.username);
      } else if (field === "password") {
        result = validatePassword(formData.password);
      }

      if (result && !result.isValid) {
        setErrors((prev) => ({ ...prev, [field]: result.error }));
      }
    },
    [formData],
  );

  /**
   * Reset form to initial state.
   */
  const resetForm = useCallback((): void => {
    setFormData(FORM_DATA_INIT_STATE);
    setErrors({});
  }, []);

  /**
   * Handle form submission.
   */
  const handleSubmit = useCallback(
    async (e: React.FormEvent): Promise<void> => {
      e.preventDefault();

      // Validate all fields
      const usernameResult = validateLogin(formData.username);
      const passwordResult = validatePassword(formData.password);

      const newErrors: ILoginFormErrors = {};
      if (!usernameResult.isValid) newErrors.username = usernameResult.error;
      if (!passwordResult.isValid) newErrors.password = passwordResult.error;

      if (Object.keys(newErrors).length > 0) {
        setErrors(newErrors);
        return;
      }

      // Submit to API
      try {
        await login(formData).unwrap();

        // Success flow
        onSuccess?.();
        navigate("/disk", { replace: true });
      } catch (error: unknown) {
        // Error handling
        const message =
          error && typeof error === "object" && "data" in error
            ? (error as { data?: { detail?: string } }).data?.detail
            : "Ошибка входа. Проверьте логин и пароль.";

        setErrors((prev) => ({ ...prev, submit: message as string }));
        onError?.(message as string);
      }
    },
    [formData, login, navigate, onSuccess, onError],
  );

  return {
    // Form state
    formData,
    errors,
    isSubmitting: isLoading,

    // Handlers
    handleChange,
    handleBlur,
    handleSubmit,
    resetForm,
  };
};
