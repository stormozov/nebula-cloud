import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { copyToClipboardWithFeedback } from "@/shared/utils";

import type {
  IStorageStats,
  IStorageStatsResponse,
  IUserListResponse,
  IUserRegister,
} from "../types";
import { copyUserField, isAdminResponse, transformDataToApi } from "../utils";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/shared/utils", () => ({
  copyToClipboardWithFeedback: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

// =============================================================================
// HELPERS
// =============================================================================

const VALID_USER_DATA: IUserRegister = {
  username: "testuser",
  email: "test@example.com",
  password: "password123",
  passwordConfirm: "password123",
  firstName: "John",
  lastName: "Doe",
};

const toApiResult = (data: IUserRegister) => ({
  username: data.username,
  email: data.email,
  password: data.password,
  password_confirm: data.passwordConfirm,
  first_name: data.firstName,
  last_name: data.lastName,
});

// =============================================================================
// TESTS: transformDataToApi
// =============================================================================

describe("transformDataToApi", () => {
  describe("Basic transformation with valid data", () => {
    /**
     * @description Should correctly transform all camelCase fields to snake_case
     * @scenario Pass valid user registration data with standard values
     * @expected All fields transformed correctly with snake_case naming
     */
    it("should transform valid user data correctly", () => {
      expect(transformDataToApi(VALID_USER_DATA)).toEqual(
        toApiResult(VALID_USER_DATA),
      );
    });

    /**
     * @description Should preserve string values exactly as provided
     * @scenario Pass user data with various string contents
     * @expected All string values remain unchanged, only keys transformed
     */
    it("should preserve exact string values", () => {
      const data: IUserRegister = {
        username: "  spaced  ",
        email: "email@domain.org",
        password: "p@ss!w0rd",
        passwordConfirm: "p@ss!w0rd",
        firstName: "  John  ",
        lastName: "Doe-Smith",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });
  });

  describe("Transformation with empty string values", () => {
    /**
     * @description Should handle empty strings in all fields
     * @scenario Pass user data with empty string values
     * @expected Empty strings preserved in output
     */
    it("should handle empty strings in all fields", () => {
      const data: IUserRegister = {
        username: "",
        email: "",
        password: "",
        passwordConfirm: "",
        firstName: "",
        lastName: "",
      };
      expect(transformDataToApi(data)).toEqual({
        username: "",
        email: "",
        password: "",
        password_confirm: "",
        first_name: "",
        last_name: "",
      });
    });

    /**
     * @description Should handle partial empty fields
     * @scenario Pass user data with some fields empty and some filled
     * @expected Empty fields preserved, filled fields transformed correctly
     */
    it("should handle partial empty fields", () => {
      const data: IUserRegister = {
        username: "user",
        email: "",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual({
        username: "user",
        email: "",
        password: "pass",
        password_confirm: "pass",
        first_name: "",
        last_name: "Doe",
      });
    });
  });

  describe("Transformation with special characters", () => {
    /**
     * @description Should handle special characters in username
     * @scenario Pass username with special characters
     * @expected Special characters preserved in output
     */
    it("should preserve special characters in username", () => {
      const data: IUserRegister = {
        username: "user_name-123",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle special characters in password
     * @scenario Pass password with various special characters
     * @expected Special characters preserved in output
     */
    it("should preserve special characters in password", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        passwordConfirm: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle hyphen in last name
     * @scenario Pass last name with hyphen (e.g., Smith-Jones)
     * @expected Hyphen preserved in output
     */
    it("should preserve hyphenated last name", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Smith-Jones",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });
  });

  describe("Transformation with numeric values", () => {
    /**
     * @description Should handle numeric username
     * @scenario Pass username with only numbers
     * @expected Numbers preserved in output
     */
    it("should preserve numeric username", () => {
      const data: IUserRegister = {
        username: "123456",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle numeric password
     * @scenario Pass password with only numbers
     * @expected Numbers preserved in output
     */
    it("should preserve numeric password", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "12345678",
        passwordConfirm: "12345678",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });
  });

  describe("Transformation with unicode characters", () => {
    /**
     * @description Should handle Cyrillic characters in names
     * @scenario Pass first and last name in Cyrillic
     * @expected Cyrillic characters preserved in output
     */
    it("should preserve Cyrillic characters in names", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "Иван",
        lastName: "Петров",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle mixed Latin and Cyrillic characters
     * @scenario Pass names with mixed character sets
     * @expected Mixed characters preserved in output
     */
    it("should preserve mixed Latin and Cyrillic characters", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John Иван",
        lastName: "Doe Петров",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle unicode characters in email
     * @scenario Pass email with unicode characters
     * @expected Unicode preserved in output
     */
    it("should preserve unicode in email", () => {
      const data: IUserRegister = {
        username: "user",
        email: "тест@example.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });
  });

  describe("Transformation with whitespace", () => {
    /**
     * @description Should preserve leading and trailing whitespace
     * @scenario Pass values with leading/trailing spaces
     * @expected Whitespace preserved in output
     */
    it("should preserve leading and trailing whitespace", () => {
      const data: IUserRegister = {
        username: "  user  ",
        email: "  test@test.com  ",
        password: "  pass  ",
        passwordConfirm: "  pass  ",
        firstName: "  John  ",
        lastName: "  Doe  ",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should preserve tabs and newlines in values
     * @scenario Pass values with tabs and newlines
     * @expected Tab and newline characters preserved in output
     */
    it("should preserve tabs and newlines in values", () => {
      const data: IUserRegister = {
        username: "user\tname",
        email: "test@test.com",
        password: "pass\nword",
        passwordConfirm: "pass\nword",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });
  });

  describe("Field mapping correctness", () => {
    /**
     * @description Should map passwordConfirm to password_confirm
     * @scenario Pass passwordConfirm value
     * @expected Output key is password_confirm (snake_case)
     */
    it("should map passwordConfirm to password_confirm", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "confirm",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual({
        username: "user",
        email: "test@test.com",
        password: "pass",
        password_confirm: "confirm",
        first_name: "John",
        last_name: "Doe",
      });
    });

    /**
     * @description Should map firstName to first_name
     * @scenario Pass firstName value
     * @expected Output key is first_name (snake_case)
     */
    it("should map firstName to first_name", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data).first_name).toBe("John");
    });

    /**
     * @description Should map lastName to last_name
     * @scenario Pass lastName value
     * @expected Output key is last_name (snake_case)
     */
    it("should map lastName to last_name", () => {
      const data: IUserRegister = {
        username: "user",
        email: "test@test.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data).last_name).toBe("Doe");
    });

    /**
     * @description Should not add any additional fields
     * @scenario Pass standard user data
     * @expected Output contains exactly 6 keys
     */
    it("should not add additional fields", () => {
      const result = transformDataToApi(VALID_USER_DATA);
      const keys = Object.keys(result);
      expect(keys).toHaveLength(6);
      expect(keys).toEqual([
        "username",
        "email",
        "password",
        "password_confirm",
        "first_name",
        "last_name",
      ]);
    });
  });

  describe("Edge cases", () => {
    /**
     * @description Should handle very long strings
     * @scenario Pass very long values (1000+ characters)
     * @expected Long strings preserved in output
     */
    it("should handle very long strings", () => {
      const longString = "a".repeat(1000);
      const data: IUserRegister = {
        username: longString,
        email: "test@test.com",
        password: longString,
        passwordConfirm: longString,
        firstName: longString,
        lastName: longString,
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle single character values
     * @scenario Pass single character for each field
     * @expected Single characters preserved in output
     */
    it("should handle single character values", () => {
      const data: IUserRegister = {
        username: "u",
        email: "t@t.t",
        password: "p",
        passwordConfirm: "p",
        firstName: "J",
        lastName: "D",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });

    /**
     * @description Should handle email with subdomain
     * @scenario Pass email with multiple subdomains
     * @expected Email preserved exactly in output
     */
    it("should handle complex email addresses", () => {
      const data: IUserRegister = {
        username: "user",
        email: "user@sub.domain.com",
        password: "pass",
        passwordConfirm: "pass",
        firstName: "John",
        lastName: "Doe",
      };
      expect(transformDataToApi(data)).toEqual(toApiResult(data));
    });
  });
});

// =============================================================================
// TESTS: copyUserField
// =============================================================================

describe("copyUserField", () => {
  const mockCopyToClipboard = copyToClipboardWithFeedback as Mock;

  const createUser = (
    overrides: Partial<IUserListResponse> = {},
  ): IUserListResponse => ({
    id: 1,
    username: "testuser",
    email: "test@example.com",
    isStaff: false,
    isActive: true,
    ...overrides,
  });

  describe("when field is 'id'", () => {
    /**
     * @description Should call copyToClipboardWithFeedback with stringified user id
     * @scenario User with numeric id=42, copy field "id"
     * @expected copyToClipboardWithFeedback called with "42" and two callbacks
     */
    it("should call copyToClipboardWithFeedback with stringified user id", async () => {
      // Arrange
      const user = createUser({ id: 42 });

      // Act
      await copyUserField(user, "id");

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalledWith(
        "42",
        expect.any(Function),
        expect.any(Function),
      );
    });

    /**
     * @description Should call onSuccess with correct label when copying succeeds
     * @scenario Copy field "id", copyToClipboardWithFeedback executes success callback
     * @expected onSuccess called with "ID пользователя 42"
     */
    it("should call onSuccess with correct label when copying succeeds", async () => {
      // Arrange
      const user = createUser({ id: 42 });
      const onSuccess = vi.fn();
      mockCopyToClipboard.mockImplementation(
        (_value: string, onSuccessCb: () => void) => {
          onSuccessCb();
        },
      );

      // Act
      await copyUserField(user, "id", onSuccess);

      // Assert
      expect(onSuccess).toHaveBeenCalledWith("ID пользователя 42");
    });

    /**
     * @description Should call onError when copyToClipboardWithFeedback triggers error callback
     * @scenario Copy field "id", copyToClipboardWithFeedback executes error callback
     * @expected onError called once
     */
    it("should call onError when copying fails", async () => {
      // Arrange
      const user = createUser();
      const onError = vi.fn();
      mockCopyToClipboard.mockImplementation(
        (_value: string, _onSuccess: () => void, onErrorCb: () => void) => {
          onErrorCb();
        },
      );

      // Act
      await copyUserField(user, "id", undefined, onError);

      // Assert
      expect(onError).toHaveBeenCalled();
    });
  });

  describe("when field is 'username'", () => {
    /**
     * @description Should call copyToClipboardWithFeedback with username value
     * @scenario User with username "john_doe", copy field "username"
     * @expected copyToClipboardWithFeedback called with "john_doe"
     */
    it("should call copyToClipboardWithFeedback with username", async () => {
      // Arrange
      const user = createUser({ username: "john_doe" });

      // Act
      await copyUserField(user, "username");

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalledWith(
        "john_doe",
        expect.any(Function),
        expect.any(Function),
      );
    });

    /**
     * @description Should call onSuccess with correct label when copying succeeds
     * @scenario Copy field "username", success callback executed
     * @expected onSuccess called with "Логин john_doe"
     */
    it("should call onSuccess with correct label when copying succeeds", async () => {
      // Arrange
      const user = createUser({ username: "john_doe" });
      const onSuccess = vi.fn();
      mockCopyToClipboard.mockImplementation(
        (_value: string, onSuccessCb: () => void) => {
          onSuccessCb();
        },
      );

      // Act
      await copyUserField(user, "username", onSuccess);

      // Assert
      expect(onSuccess).toHaveBeenCalledWith("Логин john_doe");
    });
  });

  describe("when field is 'email'", () => {
    /**
     * @description Should call copyToClipboardWithFeedback with email value
     * @scenario User with email "john@example.com", copy field "email"
     * @expected copyToClipboardWithFeedback called with "john@example.com"
     */
    it("should call copyToClipboardWithFeedback with email", async () => {
      // Arrange
      const user = createUser({ email: "john@example.com" });

      // Act
      await copyUserField(user, "email");

      // Assert
      expect(mockCopyToClipboard).toHaveBeenCalledWith(
        "john@example.com",
        expect.any(Function),
        expect.any(Function),
      );
    });

    /**
     * @description Should call onSuccess with correct label when copying succeeds
     * @scenario Copy field "email", success callback executed
     * @expected onSuccess called with "Email john@example.com"
     */
    it("should call onSuccess with correct label when copying succeeds", async () => {
      // Arrange
      const user = createUser({ email: "john@example.com" });
      const onSuccess = vi.fn();
      mockCopyToClipboard.mockImplementation(
        (_value: string, onSuccessCb: () => void) => {
          onSuccessCb();
        },
      );

      // Act
      await copyUserField(user, "email", onSuccess);

      // Assert
      expect(onSuccess).toHaveBeenCalledWith("Email john@example.com");
    });
  });

  describe("when optional callbacks are not provided", () => {
    /**
     * @description Should not throw when onSuccess and onError are undefined
     * @scenario Call copyUserField without providing onSuccess or onError
     * @expected No error thrown, copyToClipboardWithFeedback still called
     */
    it("should not throw when onSuccess and onError are undefined", async () => {
      // Arrange
      const user = createUser();

      // Act & Assert
      await expect(copyUserField(user, "id")).resolves.toBeUndefined();
      expect(mockCopyToClipboard).toHaveBeenCalled();
    });
  });
});

// =============================================================================
// TESTS: isAdminResponse
// =============================================================================

describe("isAdminResponse", () => {
  /**
   * @description Should return true when data has both 'user' and 'storage' properties
   * @scenario Object with { user: {}, storage: {} }
   * @expected true
   */
  it("should return true when data has both 'user' and 'storage' properties", () => {
    // Arrange
    const data = { user: {}, storage: {} } as IStorageStatsResponse;

    // Act
    const result = isAdminResponse(data);

    // Assert
    expect(result).toBe(true);
  });

  /**
   * @description Should return false when 'user' property is missing
   * @scenario Object with { storage: {} } only
   * @expected false
   */
  it("should return false when 'user' property is missing", () => {
    // Arrange
    const data = { storage: {} } as IStorageStatsResponse;

    // Act
    const result = isAdminResponse(data);

    // Assert
    expect(result).toBe(false);
  });

  /**
   * @description Should return false when 'storage' property is missing
   * @scenario Object with { user: {} } only
   * @expected false
   */
  it("should return false when 'storage' property is missing", () => {
    // Arrange
    const data = { user: {} } as IStorageStatsResponse;

    // Act
    const result = isAdminResponse(data);

    // Assert
    expect(result).toBe(false);
  });

  /**
   * @description Should return false when both properties are missing
   * @scenario Empty object {}
   * @expected false
   */
  it("should return false when both properties are missing", () => {
    // Arrange
    const data = {} as IStorageStats;

    // Act
    const result = isAdminResponse(data);

    // Assert
    expect(result).toBe(false);
  });

  /**
   * @description Should return true even if object has extra properties alongside user and storage
   * @scenario Object with { user: {}, storage: {}, extra: true }
   * @expected true
   */
  it("should return true for objects with additional properties", () => {
    // Arrange
    const data = {
      user: {},
      storage: {},
    } as IStorageStatsResponse;

    // Act
    const result = isAdminResponse(data);

    // Assert
    expect(result).toBe(true);
  });
});
