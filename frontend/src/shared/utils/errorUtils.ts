import type { SerializedError } from "@reduxjs/toolkit";
import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";

function isFetchBaseQueryError(error: unknown): error is FetchBaseQueryError {
  return typeof error === "object" && error !== null && "status" in error;
}

function isSerializedError(error: unknown): error is SerializedError {
  return typeof error === "object" && error !== null && "message" in error;
}

export const getErrorMessage = (error: unknown): string | null => {
  if (!error || typeof error !== "object") return null;

  if (isFetchBaseQueryError(error)) {
    if (error.status === 401) return null;
    const data = error.data as { detail?: string } | undefined;
    return data?.detail || `Ошибка ${error.status}`;
  }

  if (isSerializedError(error)) {
    return error.message || "Неизвестная ошибка";
  }

  return "Не удалось загрузить файлы";
};
