import type { MockedFunction } from "vitest";

import type { useLoginMutation } from "@/entities/user";

export type MockLoginMutation = MockedFunction<
  ReturnType<typeof useLoginMutation>[0]
>;

export interface ILoginSuccessResponse {
  access: string;
  refresh: string;
}

export interface IValidationError {
  isValid: false;
  error: string;
}

export interface IValidationSuccess {
  isValid: true;
}

export type IValidationResult = IValidationSuccess | IValidationError;

export interface IDjangoApiError {
  status?: number;
  data?: Record<string, unknown> | { detail?: string };
}

export interface IMockFormEvent {
  preventDefault: () => void;
}
