import React from "react";
import { describe, expect, it } from "vitest";
import { formatDisplayContent, shouldHideBadge } from "../utils";

describe("shouldHideBadge", () => {
  describe("when dot mode is enabled", () => {
    /**
     * @description Should return false regardless of children and showZero
     * @scenario dot = true with various children (null, 0, string '0', number 5)
     * @expected Returns false in all cases
     */
    it("should return false when dot is true", () => {
      // Arrange
      const testCases = [
        { children: null, showZero: false, dot: true },
        { children: undefined, showZero: true, dot: true },
        { children: 0, showZero: false, dot: true },
        { children: "0", showZero: false, dot: true },
        { children: 5, showZero: false, dot: true },
        { children: "5", showZero: false, dot: true },
      ];

      // Act & Assert
      for (const { children, showZero, dot } of testCases) {
        expect(shouldHideBadge(children, showZero, dot)).toBe(false);
      }
    });
  });

  describe("when dot mode is disabled", () => {
    /**
     * @description Should return true when children is null or undefined
     * @scenario dot = false, showZero = false, children = null or undefined
     * @expected Returns true
     */
    it("should return true when children is null or undefined", () => {
      // Arrange
      const nullCase = { children: null, showZero: false, dot: false };
      const undefinedCase = {
        children: undefined,
        showZero: false,
        dot: false,
      };

      // Act & Assert
      expect(
        shouldHideBadge(nullCase.children, nullCase.showZero, nullCase.dot),
      ).toBe(true);
      expect(
        shouldHideBadge(
          undefinedCase.children,
          undefinedCase.showZero,
          undefinedCase.dot,
        ),
      ).toBe(true);
    });

    /**
     * @description Should return true when children is number 0 and showZero is false
     * @scenario dot = false, showZero = false, children = 0
     * @expected Returns true
     */
    it("should return true when children is number 0 and showZero is false", () => {
      // Arrange
      const children = 0;
      const showZero = false;
      const dot = false;

      // Act
      const result = shouldHideBadge(children, showZero, dot);

      // Assert
      expect(result).toBe(true);
    });

    /**
     * @description Should return false when children is number 0 and showZero is true
     * @scenario dot = false, showZero = true, children = 0
     * @expected Returns false
     */
    it("should return false when children is number 0 and showZero is true", () => {
      // Arrange
      const children = 0;
      const showZero = true;
      const dot = false;

      // Act
      const result = shouldHideBadge(children, showZero, dot);

      // Assert
      expect(result).toBe(false);
    });

    /**
     * @description Should return true when children is string "0" (parsable to 0) and showZero is false
     * @scenario dot = false, showZero = false, children = "0"
     * @expected Returns true
     */
    it('should return true when children is string "0" and showZero is false', () => {
      // Arrange
      const children = "0";
      const showZero = false;
      const dot = false;

      // Act
      const result = shouldHideBadge(children, showZero, dot);

      // Assert
      expect(result).toBe(true);
    });

    /**
     * @description Should return false when children is string "0" and showZero is true
     * @scenario dot = false, showZero = true, children = "0"
     * @expected Returns false
     */
    it('should return false when children is string "0" and showZero is true', () => {
      // Arrange
      const children = "0";
      const showZero = true;
      const dot = false;

      // Act
      const result = shouldHideBadge(children, showZero, dot);

      // Assert
      expect(result).toBe(false);
    });

    /**
     * @description Should return false when children is non-zero number (positive or negative) regardless of showZero
     * @scenario dot = false, children = 5 or -3, showZero = false/true
     * @expected Returns false
     */
    it("should return false when children is non-zero number", () => {
      // Arrange
      const testCases = [
        { children: 5, showZero: false },
        { children: 5, showZero: true },
        { children: -3, showZero: false },
        { children: -3, showZero: true },
      ];

      // Act & Assert
      for (const { children, showZero } of testCases) {
        expect(shouldHideBadge(children, showZero, false)).toBe(false);
      }
    });

    /**
     * @description Should return false when children is non-zero numeric string (e.g., "5", "-3") regardless of showZero
     * @scenario dot = false, children = "5" or "-3", showZero = false/true
     * @expected Returns false
     */
    it("should return false when children is non-zero numeric string", () => {
      // Arrange
      const testCases = [
        { children: "5", showZero: false },
        { children: "5", showZero: true },
        { children: "-3", showZero: false },
        { children: "-3", showZero: true },
      ];

      // Act & Assert
      for (const { children, showZero } of testCases) {
        expect(shouldHideBadge(children, showZero, false)).toBe(false);
      }
    });

    /**
     * @description Should return false when children is non-numeric string (e.g., "New", "99+") regardless of showZero
     * @scenario dot = false, children = "New", showZero = false/true
     * @expected Returns false
     */
    it("should return false when children is non-numeric string", () => {
      // Arrange
      const testCases = [
        { children: "New", showZero: false },
        { children: "New", showZero: true },
        { children: "99+", showZero: false },
        { children: "99+", showZero: true },
      ];

      // Act & Assert
      for (const { children, showZero } of testCases) {
        expect(shouldHideBadge(children, showZero, false)).toBe(false);
      }
    });

    /**
     * @description Should return false when children is a React element (non-primitive type)
     * @scenario dot = false, children = React.createElement('span'), showZero = false
     * @expected Returns false (default return at the end of function)
     */
    it("should return false when children is a React element", () => {
      // Arrange
      const children = React.createElement("span", null, "text");
      const showZero = false;
      const dot = false;

      // Act
      const result = shouldHideBadge(children, showZero, dot);

      // Assert
      expect(result).toBe(false);
    });
  });
});

describe("formatDisplayContent", () => {
  describe("when dot mode is enabled", () => {
    /**
     * @description Should return null for any children and any maxCount
     * @scenario dot = true with various children (number, string, null) and maxCount
     * @expected Returns null
     */
    it("should return null when dot is true", () => {
      // Arrange
      const testCases = [
        { children: 5, maxCount: 9, dot: true },
        { children: "15", maxCount: 9, dot: true },
        { children: "New", maxCount: 5, dot: true },
        { children: null, maxCount: undefined, dot: true },
      ];

      // Act & Assert
      for (const { children, maxCount, dot } of testCases) {
        expect(formatDisplayContent(children, maxCount, dot)).toBe(null);
      }
    });
  });

  describe("when dot mode is disabled", () => {
    describe("with numeric children", () => {
      /**
       * @description Should return `${maxCount}+` when children is number greater than maxCount
       * @scenario dot = false, children = 10, maxCount = 9
       * @expected Returns "9+"
       */
      // biome-ignore lint/suspicious/noTemplateCurlyInString: <is the name of the test>
      it("should return `${maxCount}+` when number children exceeds maxCount", () => {
        // Arrange
        const children = 10;
        const maxCount = 9;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe("9+");
      });

      /**
       * @description Should return original number when children is number less than or equal to maxCount
       * @scenario dot = false, children = 5, maxCount = 9
       * @expected Returns 5
       */
      it("should return original number when number children <= maxCount", () => {
        // Arrange
        const children = 5;
        const maxCount = 9;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe(5);
      });

      /**
       * @description Should return original number when maxCount is undefined
       * @scenario dot = false, children = 100, maxCount = undefined
       * @expected Returns 100
       */
      it("should return original number when maxCount is undefined", () => {
        // Arrange
        const children = 100;
        const maxCount = undefined;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe(100);
      });

      /**
       * @description Should treat negative numbers correctly (not exceeding positive maxCount)
       * @scenario dot = false, children = -5, maxCount = 9
       * @expected Returns -5
       */
      it("should return original negative number when children < maxCount", () => {
        // Arrange
        const children = -5;
        const maxCount = 9;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe(-5);
      });
    });

    describe("with string numeric children", () => {
      /**
       * @description Should return `${maxCount}+` when string numeric children parsed > maxCount
       * @scenario dot = false, children = "15", maxCount = 9
       * @expected Returns "9+"
       */
      // biome-ignore lint/suspicious/noTemplateCurlyInString: <is the name of the test>
      it("should return `${maxCount}+` when numeric string children exceeds maxCount", () => {
        // Arrange
        const children = "15";
        const maxCount = 9;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe("9+");
      });

      /**
       * @description Should return original string when numeric string children <= maxCount
       * @scenario dot = false, children = "5", maxCount = 9
       * @expected Returns "5"
       */
      it("should return original numeric string when parsed value <= maxCount", () => {
        // Arrange
        const children = "5";
        const maxCount = 9;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe("5");
      });

      /**
       * @description Should return original string when maxCount is undefined
       * @scenario dot = false, children = "100", maxCount = undefined
       * @expected Returns "100"
       */
      it("should return original numeric string when maxCount is undefined", () => {
        // Arrange
        const children = "100";
        const maxCount = undefined;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe("100");
      });
    });

    describe("with non-numeric string children", () => {
      /**
       * @description Should return original non-numeric string regardless of maxCount
       * @scenario dot = false, children = "New", maxCount = 9
       * @expected Returns "New"
       */
      it("should return original non-numeric string", () => {
        // Arrange
        const children = "New";
        const maxCount = 9;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe("New");
      });

      /**
       * @description Should return original string that includes plus sign like "99+"
       * @scenario dot = false, children = "99+", maxCount = 5
       * @expected Returns "99+"
       */
      it("should return original string when children contains plus sign", () => {
        // Arrange
        const children = "99+";
        const maxCount = 5;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe("99+");
      });
    });

    describe("with React nodes or other types", () => {
      /**
       * @description Should return original React node (e.g., JSX element) unchanged
       * @scenario dot = false, children = a plain string or object, maxCount = 5
       * @expected Returns the same children value
       */
      it("should return original React node unchanged", () => {
        // Arrange
        const children = "icon";
        const maxCount = 5;
        const dot = false;

        // Act
        const result = formatDisplayContent(children, maxCount, dot);

        // Assert
        expect(result).toBe(children);
      });

      /**
       * @description Should return null when children is null or undefined (dot = false)
       * @scenario dot = false, children = null or undefined, maxCount arbitrary
       * @expected Returns null or undefined accordingly (passthrough)
       */
      it("should return null or undefined when children is null or undefined", () => {
        // Arrange
        const nullCase = { children: null, maxCount: 9, dot: false };
        const undefinedCase = { children: undefined, maxCount: 9, dot: false };

        // Act & Assert
        expect(
          formatDisplayContent(
            nullCase.children,
            nullCase.maxCount,
            nullCase.dot,
          ),
        ).toBe(null);
        expect(
          formatDisplayContent(
            undefinedCase.children,
            undefinedCase.maxCount,
            undefinedCase.dot,
          ),
        ).toBe(undefined);
      });
    });
  });
});
