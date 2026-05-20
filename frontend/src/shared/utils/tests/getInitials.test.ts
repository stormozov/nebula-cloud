import { describe, expect, it } from "vitest";

import { getInitials } from "../getInitials";

describe("getInitials", () => {
  describe("when given a simple name", () => {
    /**
     * @description Should return uppercase initials for a two-part name with default maxLength
     * @scenario Input "John Doe", maxLength not provided
     * @expected Returns "JD"
     */
    it("should return uppercase initials for two-part name when using default maxLength", () => {
      // Arrange
      const name = "John Doe";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JD");
    });

    /**
     * @description Should return uppercase initials for a single name
     * @scenario Input "Single", default maxLength
     * @expected Returns "S"
     */
    it("should return single uppercase letter when name has one part", () => {
      // Arrange
      const name = "Single";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("S");
    });

    /**
     * @description Should truncate initials to maxLength when result exceeds it
     * @scenario Input "Alice Bob Charlie", maxLength = 2
     * @expected Returns "AB"
     */
    it("should truncate to maxLength when result exceeds specified limit", () => {
      // Arrange
      const name = "Alice Bob Charlie";
      const maxLength = 2;

      // Act
      const initials = getInitials(name, maxLength);

      // Assert
      expect(initials).toBe("AB");
    });

    /**
     * @description Should allow maxLength larger than number of parts
     * @scenario Input "Alice Bob", maxLength = 5
     * @expected Returns "AB" (full initials, no extra padding)
     */
    it("should return full initials when maxLength is larger than parts count", () => {
      // Arrange
      const name = "Alice Bob";
      const maxLength = 5;

      // Act
      const initials = getInitials(name, maxLength);

      // Assert
      expect(initials).toBe("AB");
    });
  });

  describe("when name contains extra whitespace", () => {
    /**
     * @description Should ignore empty parts caused by consecutive spaces
     * @scenario Input "John   Doe" (multiple spaces inside)
     * @expected Returns "JD" (empty strings are filtered out)
     */
    it("should ignore empty parts from consecutive spaces when name has multiple spaces", () => {
      // Arrange
      const name = "John   Doe";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JD");
    });

    /**
     * @description Should ignore leading spaces and pick first letters of actual words
     * @scenario Input "  John Doe"
     * @expected Returns "JD" — leading spaces are treated as empty parts and filtered
     */
    it("should ignore leading spaces when name starts with spaces", () => {
      // Arrange
      const name = "  John Doe";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JD");
    });

    /**
     * @description Should handle trailing spaces similarly, ignoring them
     * @scenario Input "John Doe   "
     * @expected Returns "JD" — trailing spaces produce empty parts which are omitted
     */
    it("should treat trailing spaces as empty parts when name ends with spaces", () => {
      // Arrange
      const name = "John Doe   ";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JD");
    });
  });

  describe("when name is empty or just spaces", () => {
    /**
     * @description Should return empty string when name is empty
     * @scenario Input ""
     * @expected Returns ""
     */
    it("should return empty string when name is empty", () => {
      // Arrange
      const name = "";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("");
    });

    /**
     * @description Should return empty string when name is a single space
     * @scenario Input " "
     * @expected Returns "" because the only part is empty and is filtered out
     */
    it("should return empty string when name is a single space", () => {
      // Arrange
      const name = " ";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("");
    });

    /**
     * @description Should return empty string when name is multiple spaces
     * @scenario Input "   "
     * @expected Returns "" because all parts are empty and filtered
     */
    it("should return empty string when name is multiple spaces", () => {
      // Arrange
      const name = "   ";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("");
    });
  });

  describe("when name contains lowercase or mixed case", () => {
    /**
     * @description Should always return uppercase regardless of input case
     * @scenario Input "john doe" (lowercase)
     * @expected Returns "JD"
     */
    it("should convert to uppercase when input is lowercase", () => {
      // Arrange
      const name = "john doe";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JD");
    });

    /**
     * @description Should handle mixed case
     * @scenario Input "jOhN DoE"
     * @expected Returns "JD"
     */
    it("should convert mixed case to uppercase", () => {
      // Arrange
      const name = "jOhN DoE";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JD");
    });
  });

  describe("when maxLength is 0 or negative", () => {
    /**
     * @description Should return empty string when maxLength is 0
     * @scenario Input "John Doe", maxLength = 0
     * @expected Returns "" because slice(0,0) gives empty
     */
    it("should return empty string when maxLength is 0", () => {
      // Arrange
      const name = "John Doe";
      const maxLength = 0;

      // Act
      const initials = getInitials(name, maxLength);

      // Assert
      expect(initials).toBe("");
    });

    /**
     * @description Should return trimmed string from end when maxLength is negative (slice behavior)
     * @scenario Input "John Doe", maxLength = -1
     * @expected Returns "J" because slice(0,-1) cuts off the last character
     */
    it("should return trimmed string from end when maxLength is negative (slice behavior)", () => {
      // Arrange
      const name = "John Doe";
      const maxLength = -1;

      // Act
      const initials = getInitials(name, maxLength);

      // Assert
      expect(initials).toBe("J");
    });
  });

  describe("edge cases with special characters", () => {
    /**
     * @description Should take first character of each part even if it's not a letter
     * @scenario Input "John 2 Doe"
     * @expected Returns "J2D"
     */
    it("should include non-letter first characters when parts start with digit", () => {
      // Arrange
      const name = "John 2 Doe";

      // Act
      const initials = getInitials(name, 3);

      // Assert
      expect(initials).toBe("J2D");
    });

    /**
     * @description Should not split on hyphen when name contains hyphens
     * @scenario Input "Mary-Kate Olsen"
     * @expected Returns "MO" (split on space only, "Mary-Kate" stays whole, first char "M"; "Olsen" -> "O")
     */
    it("should not split on hyphen when name contains hyphens", () => {
      // Arrange
      const name = "Mary-Kate Olsen";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("MO");
    });

    /**
     * @description Should handle accented characters
     * @scenario Input "José García"
     * @expected Returns "JG" (first characters "J" and "G")
     */
    it("should take first character of accented parts", () => {
      // Arrange
      const name = "José García";

      // Act
      const initials = getInitials(name);

      // Assert
      expect(initials).toBe("JG");
    });
  });
});
