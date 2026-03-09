/**
 * Form field values for registration.
 */
export interface IRegisterFormValues {
  username: string;
  email: string;
  password: string;
  passwordConfirm: string;
  firstName: string;
  lastName: string;
}

/**
 * Error messages for each form field.
 */
export interface IRegisterFormErrors {
  username?: string;
  email?: string;
  password?: string;
  passwordConfirm?: string;
  firstName?: string;
  lastName?: string;
  submit?: string;
}

/**
 * Touched state for form fields (tracks which fields were blurred).
 */
export interface IRegisterFormTouched {
  username: boolean;
  email: boolean;
  password: boolean;
  passwordConfirm: boolean;
  firstName: boolean;
  lastName: boolean;
}

/**
 * Interface for useRegisterForm props.
 */
export interface IUseRegisterFormProps {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

/**
 * Return type for useRegisterForm hook.
 */
export interface IUseRegisterFormReturn {
  formData: IRegisterFormValues;
  errors: IRegisterFormErrors;
  touched: IRegisterFormTouched;
  isSubmitting: boolean;

  handleChange: (field: keyof IRegisterFormValues) => (value: string) => void;
  handleBlur: (field: keyof IRegisterFormValues) => () => void;
  handleSubmit: (e: React.FormEvent) => void;
  resetForm: () => void;
}
