import type { SerializedError } from "@reduxjs/toolkit";
import type { FetchBaseQueryError } from "@reduxjs/toolkit/query";
import { describe, expect, it } from "vitest";

import { getErrorMessage } from "../errorUtils";

// =============================================================================
// Helpers for creating test data
// =============================================================================

const createFetchBaseError = (
  status: number,
  data?: unknown,
): FetchBaseQueryError => ({
  status,
  data: data ?? {},
});

const createSerializedError = (message?: string): SerializedError => ({
  message,
  name: "Error",
  stack: "stack trace",
});

// =============================================================================
// getErrorMessage tests
// =============================================================================

describe("getErrorMessage", () => {
  describe("when input is not an object", () => {
    /**
     * @description Should return null when input is null
     * @scenario Pass null to getErrorMessage
     * @expected Returns null because !error condition
     */
    it("should return null when input is null", () => {
      // Arrange
      const error = null;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });

    /**
     * @description Should return null when input is undefined
     * @scenario Pass undefined to getErrorMessage
     * @expected Returns null because !error condition
     */
    it("should return null when input is undefined", () => {
      // Arrange
      const error = undefined;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });

    /**
     * @description Should return null when input is a string (primitive)
     * @scenario Pass a string as error
     * @expected Returns null because typeof !== 'object'
     */
    it("should return null when input is a string", () => {
      // Arrange
      const error = "some error string";

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });

    /**
     * @description Should return null when input is a number
     * @scenario Pass a number as error
     * @expected Returns null
     */
    it("should return null when input is a number", () => {
      // Arrange
      const error = 404;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });

    /**
     * @description Should return null when input is a boolean
     * @scenario Pass true or false
     * @expected Returns null
     */
    it("should return null when input is a boolean", () => {
      // Arrange
      const error = true;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe("when input is a FetchBaseQueryError", () => {
    /**
     * @description Should return null for 401 status regardless of data
     * @scenario FetchBaseQueryError with status 401
     * @expected Returns null
     */
    it("should return null when status is 401", () => {
      // Arrange
      const error = createFetchBaseError(401, { detail: "Unauthorized" });

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });

    /**
     * @description Should return detail message when data.detail exists and status != 401
     * @scenario FetchBaseQueryError with status 404 and data.detail = 'Not Found'
     * @expected Returns the detail string
     */
    it("should return data.detail when data.detail exists and status is not 401", () => {
      // Arrange
      const error = createFetchBaseError(404, { detail: "Not Found" });

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Not Found");
    });

    /**
     * @description Should return formatted error with status when data.detail is missing
     * @scenario FetchBaseQueryError with status 500 and data without detail
     * @expected Returns 'Ошибка 500'
     */
    it("should return formatted error with status when data.detail is missing", () => {
      // Arrange
      const error = createFetchBaseError(500, {});

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Ошибка 500");
    });

    /**
     * @description Should return formatted error with status when data is undefined
     * @scenario FetchBaseQueryError where data property is not present
     * @expected Returns 'Ошибка <status>' using status directly
     */
    it("should return formatted error with status when data is undefined", () => {
      // Arrange
      const error = { status: 403 } as FetchBaseQueryError;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Ошибка 403");
    });

    /**
     * @description Should handle FetchBaseQueryError with status as string literal (or non-numeric)
     * @scenario Some RTK versions can have status as 'PARSING_ERROR' etc.
     * @expected Still enters this branch, data?.detail or fallback
     */
    it("should return data.detail when status is a string and data.detail exists", () => {
      // Arrange
      const error = {
        status: "FETCH_ERROR",
        data: { detail: "Network Error" },
      } as unknown as FetchBaseQueryError;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Network Error");
    });

    /**
     * @description Should return formatted error with status string when no detail
     * @scenario FetchBaseQueryError with status 'TIMEOUT' and no data
     * @expected Returns 'Ошибка TIMEOUT'
     */
    it("should return formatted error with status string when no detail", () => {
      // Arrange
      const error = {
        status: "TIMEOUT",
        data: {},
      } as unknown as FetchBaseQueryError;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Ошибка TIMEOUT");
    });
  });

  describe("when input is a SerializedError", () => {
    /**
     * @description Should return error.message when message is present
     * @scenario SerializedError with non-empty message
     * @expected Returns the message string
     */
    it("should return error.message when message exists", () => {
      // Arrange
      const error = createSerializedError("Something went wrong");

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Something went wrong");
    });

    /**
     * @description Should fallback to 'Неизвестная ошибка' when message is missing or falsy
     * @scenario SerializedError with undefined message
     * @expected Returns 'Неизвестная ошибка'
     */
    it("should return default message when error.message is undefined", () => {
      // Arrange
      const error = createSerializedError(undefined);

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Неизвестная ошибка");
    });

    /**
     * @description Should fallback to default when message is empty string
     * @scenario SerializedError with empty message
     * @expected Returns 'Неизвестная ошибка'
     */
    it("should return default message when error.message is empty string", () => {
      // Arrange
      const error = createSerializedError("");

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Неизвестная ошибка");
    });
  });

  describe("when input is a generic object not matching known types", () => {
    /**
     * @description Should return generic fallback message
     * @scenario Plain object without status or message properties
     * @expected Returns 'Не удалось загрузить файлы'
     */
    it("should return fallback message when object has no status or message", () => {
      // Arrange
      const error = { someProp: "value" };

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Не удалось загрузить файлы");
    });

    /**
     * @description Should return fallback message when object is a Date
     * @scenario Date object has typeof 'object' but no status or message
     * @expected Returns the fallback string
     */
    it("should return fallback message when input is a Date", () => {
      // Arrange
      const error = new Date();

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Не удалось загрузить файлы");
    });

    /**
     * @description Should return fallback message when object is an array
     * @scenario Arrays are objects with typeof 'object', but no status/message
     * @expected Returns the fallback string
     */
    it("should return fallback message when input is an array", () => {
      // Arrange
      const error = ["error1", "error2"];

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Не удалось загрузить файлы");
    });
  });

  describe("edge cases", () => {
    /**
     * @description Should handle FetchBaseQueryError with 401 but data containing detail
     * @scenario 401 error with detail message - ensures early return
     * @expected Returns null, ignoring detail
     */
    it("should return null for 401 even with detail present", () => {
      // Arrange
      const error = createFetchBaseError(401, { detail: "Session expired" });

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });

    /**
     * @description Should handle nested error object that has both status and message (FetchBaseQueryError takes precedence due to order)
     * @scenario Object with both status and message properties
     * @expected Treated as FetchBaseQueryError because it's checked first
     */
    it("should treat object as FetchBaseQueryError if both status and message present (order)", () => {
      // Arrange
      const error = {
        status: 404,
        message: "Ignored message",
        data: { detail: "Not found" },
      } as unknown as FetchBaseQueryError;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBe("Not found");
    });

    /**
     * @description Should return null if error is an object but status is 401 and other props exist
     * @scenario Edge: status 401 but no data
     * @expected Returns null immediately
     */
    it("should return null when status is 401 and no data", () => {
      // Arrange
      const error = { status: 401 } as FetchBaseQueryError;

      // Act
      const result = getErrorMessage(error);

      // Assert
      expect(result).toBeNull();
    });
  });
});
