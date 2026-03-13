import "./Form.scss";

/**
 * Form submit error block component.
 */
interface FormSubmitErrorBlockProps {
  errors: string;
}

/**
 * Form submit error block component.
 */
export function FormSubmitErrorBlock({ errors }: FormSubmitErrorBlockProps) {
  if (!errors) return null;
  return (
    <div className="form__submit-error" role="alert">
      {errors}
    </div>
  );
}
