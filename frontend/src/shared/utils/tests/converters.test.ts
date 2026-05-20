import { describe, expect, it } from "vitest";
import { camelToSnake, snakeToCamel } from "../converters";

// =============================================================================
// snakeToCamel tests
// =============================================================================

describe("snakeToCamel", () => {
  // ---------- helpers / factories ----------
  const primitiveValues: Array<[string, unknown]> = [
    ["string", "hello_world"],
    ["number", 42],
    ["boolean", true],
    ["null", null],
    ["undefined", undefined],
  ];

  const createNestedSnakeObj = () => ({
    first_name: "Alice",
    address_info: {
      street_name: "Main St",
      zip_code: "12345",
    },
    hobbies: ["ice_skating", "mountain_climbing"],
  });

  const createFile = () => new File([""], "test.txt", { type: "text/plain" });
  const createBlob = () => new Blob([""], { type: "text/plain" });

  // ---------------------------------------------------------------------------
  describe("when input is a primitive", () => {
    primitiveValues.forEach(([type, val]) => {
      /**
       * @description Should return the same primitive value unchanged
       * @scenario Calling snakeToCamel with a ${type} value
       * @expected The original primitive value is returned as-is
       */
      it(`should return ${type} unchanged when input is ${type}`, () => {
        // Arrange
        const input = val;

        // Act
        const result = snakeToCamel(input);

        // Assert
        expect(result).toBe(input);
      });
    });
  });

  // ---------------------------------------------------------------------------
  describe("when input is a plain object", () => {
    /**
     * @description Should convert simple snake_case keys to camelCase
     * @scenario Object with single underscore keys like { user_name: 'John' }
     * @expected Keys become user_name → userName
     */
    it("should convert simple snake_case keys to camelCase when object has single underscore", () => {
      // Arrange
      const input = { user_name: "John", first_name: "Doe" };

      // Act
      const result = snakeToCamel(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({
        userName: "John",
        firstName: "Doe",
      });
    });

    /**
     * @description Should convert multiple underscore separated keys
     * @scenario Object with keys like full_user_address_info
     * @expected Key becomes fullUserAddressInfo
     */
    it("should convert multiple underscore separated keys when object has complex keys", () => {
      // Arrange
      const input = { full_user_address_info: "NY" };

      // Act
      const result = snakeToCamel(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({ fullUserAddressInfo: "NY" });
    });

    /**
     * @description Should not modify keys already in camelCase or without underscores
     * @scenario Object with keys like userName, plain
     * @expected Keys remain exactly the same
     */
    it("should not modify keys without underscores when object has camelCase or plain keys", () => {
      // Arrange
      const input = { userName: "Bob", plain: "text" };

      // Act
      const result = snakeToCamel(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({ userName: "Bob", plain: "text" });
    });

    /**
     * @description Should handle nested objects recursively
     * @scenario Object with nested object containing snake_case keys
     * @expected All nested keys are converted recursively
     */
    it("should handle nested objects recursively when object has nested structure", () => {
      // Arrange
      const input = createNestedSnakeObj();

      // Act
      const result = snakeToCamel(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({
        firstName: "Alice",
        addressInfo: {
          streetName: "Main St",
          zipCode: "12345",
        },
        hobbies: ["ice_skating", "mountain_climbing"],
      });
    });

    /**
     * @description Should return File instance unchanged
     * @scenario Input is a File object
     * @expected The same File instance is returned, no conversion
     */
    it("should return File object unchanged when input is File", () => {
      // Arrange
      const file = createFile();

      // Act
      const result = snakeToCamel(file);

      // Assert
      expect(result).toBe(file);
    });

    /**
     * @description Should return Blob instance unchanged
     * @scenario Input is a Blob object
     * @expected The same Blob instance is returned
     */
    it("should return Blob object unchanged when input is Blob", () => {
      // Arrange
      const blob = createBlob();

      // Act
      const result = snakeToCamel(blob);

      // Assert
      expect(result).toBe(blob);
    });

    /**
     * @description Should convert keys but leave File/Blob values untouched
     * @scenario Object contains a File value under a snake_case key
     * @expected The key is converted, but the File value remains the same instance
     */
    it("should not convert File/Blob value but convert its key when object contains File", () => {
      // Arrange
      const file = createFile();
      const input = { avatar_file: file };

      // Act
      const result = snakeToCamel(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({ avatarFile: file });
      expect((result as Record<string, unknown>).avatarFile).toBe(file);
    });

    /**
     * @description Should convert Date instance to empty object (current behaviour)
     * @scenario Input is a Date object
     * @expected Date becomes an empty object because Object.entries yields nothing
     */
    it("should convert Date to empty object when input is Date", () => {
      // Arrange
      const date = new Date();

      // Act
      const result = snakeToCamel(date);

      // Assert
      expect(result).toEqual({});
    });
  });

  // ---------------------------------------------------------------------------
  describe("when input is an array", () => {
    /**
     * @description Should apply conversion to every element of the array
     * @scenario Array of snake_case objects
     * @expected Each object's keys are converted
     */
    it("should convert array of objects when input is array of snake_case objects", () => {
      // Arrange
      const input = [{ user_name: "A" }, { user_name: "B" }];

      // Act
      const result = snakeToCamel(input) as Array<Record<string, unknown>>;

      // Assert
      expect(result).toEqual([{ userName: "A" }, { userName: "B" }]);
    });

    /**
     * @description Should handle array of primitives without changes
     * @scenario Array of strings and numbers
     * @expected Same array content, no conversion
     */
    it("should return array of primitives unchanged when input is array of primitives", () => {
      // Arrange
      const input = ["hello", 42, true, null];

      // Act
      const result = snakeToCamel(input);

      // Assert
      expect(result).toEqual(input);
    });

    /**
     * @description Should handle nested arrays recursively
     * @scenario Array containing another array of snake_case objects
     * @expected Inner arrays are also converted
     */
    it("should convert nested arrays when input contains nested arrays", () => {
      // Arrange
      const input = [[{ full_name: "Nested" }]];

      // Act
      const result = snakeToCamel(input);

      // Assert
      expect(result).toEqual([[{ fullName: "Nested" }]]);
    });
  });

  // ---------------------------------------------------------------------------
  describe("edge cases", () => {
    /**
     * @description Should not mutate the original object
     * @scenario Provide an object and check after conversion
     * @expected Original object key names remain in snake_case
     */
    it("should not mutate the original object when converting", () => {
      // Arrange
      const input = { user_name: "Immutable" };
      const copy = { ...input };

      // Act
      snakeToCamel(input);

      // Assert
      expect(input).toEqual(copy);
    });

    /**
     * @description Should return empty object/array unchanged
     * @scenario Input is empty object {} or []
     * @expected Returns the same empty structure
     */
    it("should return empty object when input is empty object", () => {
      // Arrange
      const input = {};

      // Act
      const result = snakeToCamel(input);

      // Assert
      expect(result).toEqual({});
    });

    /**
     * @description Should return empty array when input is empty array
     * @scenario Input is []
     * @expected Returns []
     */
    it("should return empty array when input is empty array", () => {
      // Arrange
      const input: unknown[] = [];

      // Act
      const result = snakeToCamel(input);

      // Assert
      expect(result).toEqual([]);
    });
  });
});

// =============================================================================
// camelToSnake tests
// =============================================================================

describe("camelToSnake", () => {
  // ---------- helpers / factories ----------
  const createNestedCamelObj = () => ({
    firstName: "Alice",
    addressInfo: {
      streetName: "Main St",
      zipCode: "12345",
    },
    hobbies: ["iceSkating", "mountainClimbing"],
  });

  const createFile = () => new File([""], "test.txt", { type: "text/plain" });
  const createBlob = () => new Blob([""], { type: "text/plain" });

  // ---------------------------------------------------------------------------
  describe("when input is a primitive", () => {
    const primitiveValues: Array<[string, unknown]> = [
      ["string", "helloWorld"],
      ["number", 42],
      ["boolean", true],
      ["null", null],
      ["undefined", undefined],
    ];

    primitiveValues.forEach(([type, val]) => {
      /**
       * @description Should return the same primitive value unchanged
       * @scenario Calling camelToSnake with a ${type} value
       * @expected The original primitive value is returned as-is
       */
      it(`should return ${type} unchanged when input is ${type}`, () => {
        // Arrange
        const input = val;

        // Act
        const result = camelToSnake(input);

        // Assert
        expect(result).toBe(input);
      });
    });
  });

  // ---------------------------------------------------------------------------
  describe("when input is a plain object", () => {
    /**
     * @description Should convert simple camelCase keys to snake_case
     * @scenario Object with keys like userName, firstName
     * @expected Keys become user_name, first_name
     */
    it("should convert simple camelCase keys to snake_case when object has single word breaks", () => {
      // Arrange
      const input = { userName: "John", firstName: "Doe" };

      // Act
      const result = camelToSnake(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({
        user_name: "John",
        first_name: "Doe",
      });
    });

    /**
     * @description Should replace each uppercase letter with underscore + lowercase, even consecutively
     * @scenario Object with keys like userID, PDFParser
     * @expected Every uppercase letter is individually converted → user_i_d, _p_d_f_parser
     */
    it("should replace each uppercase letter with underscore + lowercase when object has consecutive uppercase letters", () => {
      // Arrange
      const input = { userID: 1, PDFParser: "test" };

      // Act
      const result = camelToSnake(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({
        user_i_d: 1,
        _p_d_f_parser: "test",
      });
    });

    /**
     * @description Should not modify keys already in snake_case
     * @scenario Object with keys like user_name, plain
     * @expected Keys remain exactly the same
     */
    it("should not modify keys already in snake_case when object has snake_case keys", () => {
      // Arrange
      const input = { user_name: "Bob", plain: "text" };

      // Act
      const result = camelToSnake(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({ user_name: "Bob", plain: "text" });
    });

    /**
     * @description Should handle nested objects recursively
     * @scenario Object with nested camelCase object
     * @expected All nested keys are converted to snake_case
     */
    it("should handle nested objects recursively when object has nested structure", () => {
      // Arrange
      const input = createNestedCamelObj();

      // Act
      const result = camelToSnake(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({
        first_name: "Alice",
        address_info: {
          street_name: "Main St",
          zip_code: "12345",
        },
        hobbies: ["iceSkating", "mountainClimbing"], // primitives inside array unchanged
      });
    });

    /**
     * @description Should return File instance unchanged
     * @scenario Input is a File object
     * @expected The same File instance is returned
     */
    it("should return File object unchanged when input is File", () => {
      // Arrange
      const file = createFile();

      // Act
      const result = camelToSnake(file);

      // Assert
      expect(result).toBe(file);
    });

    /**
     * @description Should return Blob instance unchanged
     * @scenario Input is a Blob object
     * @expected The same Blob instance is returned
     */
    it("should return Blob object unchanged when input is Blob", () => {
      // Arrange
      const blob = createBlob();

      // Act
      const result = camelToSnake(blob);

      // Assert
      expect(result).toBe(blob);
    });

    /**
     * @description Should convert keys but leave File/Blob values untouched
     * @scenario Object contains a File value under a camelCase key
     * @expected The key is converted, but the File value remains the same instance
     */
    it("should not convert File/Blob value but convert its key when object contains File", () => {
      // Arrange
      const file = createFile();
      const input = { avatarFile: file };

      // Act
      const result = camelToSnake(input) as Record<string, unknown>;

      // Assert
      expect(result).toEqual({ avatar_file: file });
      expect((result as Record<string, unknown>).avatar_file).toBe(file);
    });

    /**
     * @description Should convert Date instance to empty object (current behaviour)
     * @scenario Input is a Date object
     * @expected Date becomes an empty object because Object.entries yields nothing
     */
    it("should convert Date to empty object when input is Date", () => {
      // Arrange
      const date = new Date();

      // Act
      const result = camelToSnake(date);

      // Assert
      expect(result).toEqual({});
    });
  });

  // ---------------------------------------------------------------------------
  describe("when input is an array", () => {
    /**
     * @description Should apply conversion to every element of the array
     * @scenario Array of camelCase objects
     * @expected Each object's keys are converted to snake_case
     */
    it("should convert array of objects when input is array of camelCase objects", () => {
      // Arrange
      const input = [{ userName: "A" }, { userName: "B" }];

      // Act
      const result = camelToSnake(input) as Array<Record<string, unknown>>;

      // Assert
      expect(result).toEqual([{ user_name: "A" }, { user_name: "B" }]);
    });

    /**
     * @description Should handle array of primitives without changes
     * @scenario Array of strings and numbers
     * @expected Same array content, no conversion
     */
    it("should return array of primitives unchanged when input is array of primitives", () => {
      // Arrange
      const input = ["hello", 42, true, null];

      // Act
      const result = camelToSnake(input);

      // Assert
      expect(result).toEqual(input);
    });

    /**
     * @description Should handle nested arrays recursively
     * @scenario Array containing another array of camelCase objects
     * @expected Inner arrays are also converted
     */
    it("should convert nested arrays when input contains nested arrays", () => {
      // Arrange
      const input = [[{ fullName: "Nested" }]];

      // Act
      const result = camelToSnake(input);

      // Assert
      expect(result).toEqual([[{ full_name: "Nested" }]]);
    });
  });

  // ---------------------------------------------------------------------------
  describe("edge cases", () => {
    /**
     * @description Should not mutate the original object
     * @scenario Provide an object and check after conversion
     * @expected Original object key names remain in camelCase
     */
    it("should not mutate the original object when converting", () => {
      // Arrange
      const input = { userName: "Immutable" };
      const copy = { ...input };

      // Act
      camelToSnake(input);

      // Assert
      expect(input).toEqual(copy);
    });

    /**
     * @description Should return empty object/array unchanged
     * @scenario Input is empty object {} or []
     * @expected Returns the same empty structure
     */
    it("should return empty object when input is empty object", () => {
      // Arrange
      const input = {};

      // Act
      const result = camelToSnake(input);

      // Assert
      expect(result).toEqual({});
    });

    /**
     * @description Should return empty array when input is empty array
     * @scenario Input is []
     * @expected Returns []
     */
    it("should return empty array when input is empty array", () => {
      // Arrange
      const input: unknown[] = [];

      // Act
      const result = camelToSnake(input);

      // Assert
      expect(result).toEqual([]);
    });
  });
});
