/**
 * Parsed error result with field-specific and generic errors.
 */
export interface IParsedApiErrors {
  fieldErrors: Record<string, string>;
  submitError?: string;
}

/**
 * Paginated API response.
 */
export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}
