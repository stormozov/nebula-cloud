/**
 * Parsed error result with field-specific and generic errors.
 */
export interface IParsedApiErrors {
  fieldErrors: Record<string, string>;
  submitError?: string;
}
