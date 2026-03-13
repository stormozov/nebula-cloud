/**
 * Interface for login form values.
 */
export interface ILoginFormValues {
  username: string;
  password: string;
}

/**
 * Interface for login form errors.
 */
export interface ILoginFormErrors {
  username?: string;
  password?: string;
  submit?: string;
}

/**
 * Interface for useLoginForm props.
 */
export interface IUseLoginFormProps {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

/**
 * Interface for useLoginForm return value.
 */
export interface IUseLoginFormReturn {
  formData: ILoginFormValues;
  errors: ILoginFormErrors;
  isSubmitting: boolean;

  handleChange: (field: keyof ILoginFormValues) => (value: string) => void;
  handleBlur: (field: keyof ILoginFormValues) => () => void;
  handleSubmit: (e: React.FormEvent) => void;
  resetForm: () => void;
}
