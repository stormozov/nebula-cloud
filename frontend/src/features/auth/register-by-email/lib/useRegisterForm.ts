import { useCallback, useState } from "react";
import { useNavigate } from "react-router";

import { useRegisterMutation } from "@/entities/user";
import { hasFieldErrors, parseDjangoApiErrors } from "@/shared/api";
import { isFormValid } from "@/shared/utils";
import { validateRegistrationForm } from "@/shared/validators";

import type {
  IRegisterFormErrors,
  IRegisterFormTouched,
  IRegisterFormValues,
  IUseRegisterFormProps,
  IUseRegisterFormReturn,
} from "./types";
import {
  createInitialFormValues,
  createInitialTouchedState,
  mapValidationResultsToErrors,
} from "./utils";

/**
 * Custom hook for registration form logic.
 *
 * Handles validation, submission, and error management.
 *
 * @param {Object} options - Hook options
 * @param {() => void} options.onSuccess - Callback on successful registration
 * @param {(error: string) => void} options.onError - Callback on registration
 *  error
 *
 * @returns {IUseRegisterFormReturn} Form state and handlers
 *
 * @example
 * const {
 *   formData, errors, isSubmitting, handleChange, handleSubmit
 * } = useRegisterForm({
 *   onSuccess: () => navigate('/disk'),
 *   onError: (msg) => setSubmitError(msg),
 * });
 */
export const useRegisterForm = ({
  onSuccess,
  onError,
}: IUseRegisterFormProps): IUseRegisterFormReturn => {
  const navigate = useNavigate();
  const [register, { isLoading }] = useRegisterMutation();

  const [formData, setFormData] = useState<IRegisterFormValues>(
    createInitialFormValues(),
  );

  const [touched, setTouched] = useState<IRegisterFormTouched>(
    createInitialTouchedState(),
  );

  const [errors, setErrors] = useState<IRegisterFormErrors>({});

  /**
   * Handle field value change.
   * Clears error for the field when user starts typing.
   */
  const handleChange = useCallback(
    (field: keyof IRegisterFormValues) =>
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
   * Sets touched state and validates only if field was modified.
   */
  const handleBlur = useCallback(
    (field: keyof IRegisterFormValues) => (): void => {
      // Mark field as touched
      setTouched((prev) => ({ ...prev, [field]: true }));

      // Validate all fields to catch cross-field validation (password confirm)
      const validationResults = validateRegistrationForm(formData);
      const newErrors = mapValidationResultsToErrors(validationResults, {
        ...touched,
        [field]: true,
      });

      setErrors(newErrors);
    },
    [formData, touched],
  );

  /**
   * Reset form to initial state.
   */
  const resetForm = useCallback((): void => {
    setFormData(createInitialFormValues());
    setTouched(createInitialTouchedState());
    setErrors({});
  }, []);

  /**
   * Handle form submission.
   * Validates all fields and submits to API if valid.
   */
  const handleSubmit = useCallback(
    async (e: React.FormEvent): Promise<void> => {
      e.preventDefault();

      // Validate all fields
      const validationResults = validateRegistrationForm(formData);

      if (!isFormValid(validationResults)) {
        // Mark all fields as touched to show errors
        setTouched({
          username: true,
          email: true,
          password: true,
          passwordConfirm: true,
          firstName: true,
          lastName: true,
        });
        setErrors(
          mapValidationResultsToErrors(validationResults, {
            username: true,
            email: true,
            password: true,
            passwordConfirm: true,
            firstName: true,
            lastName: true,
          }),
        );
        return;
      }

      // Submit to API
      try {
        await register(formData).unwrap();

        // Success flow
        onSuccess?.();
        navigate("/disk", { replace: true });
      } catch (error: unknown) {
        let apiFieldErrors: IRegisterFormErrors = {};
        let submitError: string | undefined;

        if (error && typeof error === "object" && "data" in error) {
          const errorData = (error as { data?: unknown }).data;
          const parsedErrors = parseDjangoApiErrors(errorData);

          apiFieldErrors = parsedErrors.fieldErrors as IRegisterFormErrors;
          submitError = parsedErrors.submitError;
        }

        if (!hasFieldErrors(apiFieldErrors) && !submitError) {
          // If no field errors, set generic submit error
          submitError = "Ошибка регистрации. Попробуйте позже.";
        }

        setErrors((prev) => ({
          ...prev,
          ...apiFieldErrors,
          submit: submitError,
        }));

        onError?.(
          submitError ||
            Object.values(apiFieldErrors)[0] ||
            "Ошибка регистрации",
        );
      }
    },
    [formData, register, navigate, onSuccess, onError],
  );

  return {
    // Form state
    formData,
    errors,
    touched,
    isSubmitting: isLoading,

    // Handlers
    handleChange,
    handleBlur,
    handleSubmit,
    resetForm,
  };
};
