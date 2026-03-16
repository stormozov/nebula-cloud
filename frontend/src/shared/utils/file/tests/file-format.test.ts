import { beforeEach, describe, expect, it, vi } from "vitest";

import { formatFileSize, parseFileSize } from "../file-format";

describe("file-format", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ---------------------------------------------------------------------------
  // FORMAT FILE SIZE
  // ---------------------------------------------------------------------------

  /**
   * Tests for formatFileSize function
   */
  describe("formatFileSize", () => {
    /**
     * Success scenarios - valid inputs with expected outputs
     */
    describe("success scenarios", () => {
      /**
       * @description Handles zero bytes
       * @scenario Input is 0 bytes
       * @expected Returns "0 Б"
       */
      it.each([
        { bytes: 0, expected: "0 Б", desc: "zero bytes" },
      ])("should format $desc: $bytes bytes → $expected", ({
        bytes,
        expected,
      }) => {
        expect(formatFileSize(bytes)).toBe(expected);
      });

      /**
       * @description Handles bytes unit
       * @scenario Input is less than 1024 bytes
       * @expected Returns value in Б with correct decimals
       */
      it.each([
        { bytes: 500, decimals: 0, expected: "500 Б" },
        { bytes: 500, decimals: 2, expected: "500.00 Б" },
        { bytes: 1023, decimals: 2, expected: "1023.00 Б" },
      ])("should format bytes: $bytes bytes, $decimals decimals → $expected", ({
        bytes,
        decimals,
        expected,
      }) => {
        expect(formatFileSize(bytes, decimals)).toBe(expected);
      });

      /**
       * @description Handles kilobytes unit
       * @scenario Input is between 1024 and 1048575 bytes
       * @expected Returns value in КБ with correct decimals
       */
      it.each([
        { bytes: 1024, expected: "1.00 КБ" },
        { bytes: 1536, expected: "1.50 КБ" },
        { bytes: 1_048_575, expected: "1024.00 КБ" },
      ])("should format kilobytes: $bytes bytes → $expected", ({
        bytes,
        expected,
      }) => {
        expect(formatFileSize(bytes)).toBe(expected);
      });

      /**
       * @description Handles megabytes unit
       * @scenario Input is between 1048576 and 1073741823 bytes
       * @expected Returns value in МБ with correct decimals
       */
      it.each([
        { bytes: 1_048_576, expected: "1.00 МБ" },
        { bytes: 1_572_864, expected: "1.50 МБ" },
        { bytes: 1_073_741_823, expected: "1024.00 МБ" },
      ])("should format megabytes: $bytes bytes → $expected", ({
        bytes,
        expected,
      }) => {
        expect(formatFileSize(bytes)).toBe(expected);
      });

      /**
       * @description Handles gigabytes unit
       * @scenario Input is between 1073741824 and 1099511627775 bytes
       * @expected Returns value in ГБ with correct decimals
       */
      it.each([
        { bytes: 1_073_741_824, expected: "1.00 ГБ" },
        { bytes: 1_610_612_736, expected: "1.50 ГБ" },
        { bytes: 1_099_511_627_775, expected: "1024.00 ГБ" },
      ])("should format gigabytes: $bytes bytes → $expected", ({
        bytes,
        expected,
      }) => {
        expect(formatFileSize(bytes)).toBe(expected);
      });

      /**
       * @description Handles terabytes unit
       * @scenario Input is 1099511627776 bytes or more
       * @expected Returns value in ТБ with correct decimals
       */
      it.each([
        { bytes: 1_099_511_627_776, expected: "1.00 ТБ" },
        { bytes: 1_649_267_441_664, expected: "1.50 ТБ" },
      ])("should format terabytes: $bytes bytes → $expected", ({
        bytes,
        expected,
      }) => {
        expect(formatFileSize(bytes)).toBe(expected);
      });

      /**
       * @description Handles custom decimal places
       * @scenario Different decimal precision specified
       * @expected Returns value with specified decimal places
       */
      it.each([
        { bytes: 1024, decimals: 0, expected: "1 КБ" },
        { bytes: 1024, decimals: 1, expected: "1.0 КБ" },
        { bytes: 1024, decimals: 3, expected: "1.000 КБ" },
        { bytes: 1536, decimals: 4, expected: "1.5000 КБ" },
      ])("should respect decimal places: $bytes bytes, $decimals decimals → $expected", ({
        bytes,
        decimals,
        expected,
      }) => {
        expect(formatFileSize(bytes, decimals)).toBe(expected);
      });
    });

    /**
     * Edge cases - boundary values and special behaviors
     */
    describe("edge cases", () => {
      /**
       * @description Handles floating point precision edge cases
       * @scenario Values near unit boundaries
       * @expected Correctly selects unit based on log calculation
       */
      it.each([
        { bytes: 1023, expected: "1023.00 Б", desc: "B/KB boundary" },
        { bytes: 1024, expected: "1.00 КБ", desc: "KB start" },
        { bytes: 1_048_575, expected: "1024.00 КБ", desc: "KB/MB boundary" },
        { bytes: 1_048_576, expected: "1.00 МБ", desc: "MB start" },
        {
          bytes: 1_073_741_823,
          expected: "1024.00 МБ",
          desc: "MB/GB boundary",
        },
        { bytes: 1_073_741_824, expected: "1.00 ГБ", desc: "GB start" },
      ])("should handle $desc: $bytes bytes → $expected", ({
        bytes,
        expected,
      }) => {
        expect(formatFileSize(bytes)).toBe(expected);
      });

      /**
       * @description Handles negative bytes
       * @scenario Input is negative number
       * @expected Preserves sign in output (implementation detail)
       */
      it.each([
        { bytes: -1024, expected: "-1.00 КБ" },
        { bytes: -500, decimals: 0, expected: "-500 Б" },
        { bytes: -1_048_576, expected: "-1.00 МБ" },
      ])("should preserve sign for negative: $bytes → $expected", ({
        bytes,
        decimals = 2,
        expected,
      }) => {
        expect(formatFileSize(bytes, decimals)).toBe(expected);
      });

      /**
       * @description Handles maximum unit boundary
       * @scenario Input exceeds terabytes
       * @expected Caps at ТБ unit (doesn't go beyond)
       */
      it("should cap at terabytes for very large values", () => {
        const largeValue = 1024 ** 5; // Petabyte
        expect(formatFileSize(largeValue)).toContain("ТБ");
      });
    });
  });

  // ---------------------------------------------------------------------------
  // PARSE FILE SIZE
  // ---------------------------------------------------------------------------

  /**
   * Tests for parseFileSize function
   */
  describe("parseFileSize", () => {
    /**
     * Success scenarios - valid inputs that should parse correctly
     */
    describe("success scenarios", () => {
      /**
       * @description Parses bytes string
       * @scenario Input is valid bytes format
       * @expected Returns correct byte value
       */
      it.each([
        { input: "500 Б", expected: 500 },
        { input: "0 Б", expected: 0 },
        { input: "1023 Б", expected: 1023 },
      ])("should parse bytes: '$input' → $expected", ({ input, expected }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Parses kilobytes string
       * @scenario Input is valid КБ format
       * @expected Returns correct byte value (value * 1024)
       */
      it.each([
        { input: "1.00 КБ", expected: 1024 },
        { input: "1.50 КБ", expected: 1536 },
        { input: "2 КБ", expected: 2048 },
      ])("should parse kilobytes: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Parses megabytes string
       * @scenario Input is valid МБ format
       * @expected Returns correct byte value (value * 1024^2)
       */
      it.each([
        { input: "1.00 МБ", expected: 1_048_576 },
        { input: "1.50 МБ", expected: 1_572_864 },
        { input: "2 МБ", expected: 2_097_152 },
      ])("should parse megabytes: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Parses gigabytes string
       * @scenario Input is valid ГБ format
       * @expected Returns correct byte value (value * 1024^3)
       */
      it.each([
        { input: "1.00 ГБ", expected: 1_073_741_824 },
        { input: "1.50 ГБ", expected: 1_610_612_736 },
        { input: "2 ГБ", expected: 2_147_483_648 },
      ])("should parse gigabytes: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Parses terabytes string
       * @scenario Input is valid ТБ format
       * @expected Returns correct byte value (value * 1024^4)
       */
      it.each([
        { input: "1.00 ТБ", expected: 1_099_511_627_776 },
        { input: "1.50 ТБ", expected: 1_649_267_441_664 },
      ])("should parse terabytes: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Handles case insensitivity
       * @scenario Input has mixed case units
       * @expected Parses correctly regardless of case
       */
      it.each([
        { input: "1.00 кб", expected: 1024 },
        { input: "1.00 Кб", expected: 1024 },
        { input: "1.00 мб", expected: 1_048_576 },
        { input: "1.00 Гб", expected: 1_073_741_824 },
        { input: "1.00 тб", expected: 1_099_511_627_776 },
      ])("should handle case insensitivity: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Handles decimal values
       * @scenario Input has decimal numbers
       * @expected Parses decimal values correctly with rounding
       */
      it.each([
        { input: "0.5 КБ", expected: 512 },
        { input: "0.25 МБ", expected: 262_144 },
        { input: "1.75 ГБ", expected: 1_879_048_192 },
      ])("should handle decimal values: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Handles integer values without decimals
       * @scenario Input has whole numbers
       * @expected Parses correctly
       */
      it.each([
        { input: "1 КБ", expected: 1024 },
        { input: "10 МБ", expected: 10_485_760 },
        { input: "5 ГБ", expected: 5_368_709_120 },
      ])("should handle integer values: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Handles trailing whitespace
       * @scenario Input has extra spaces at end
       * @expected Parses correctly (regex has no $ anchor)
       */
      it.each([
        { input: "1.00 КБ ", expected: 1024, desc: "trailing space" },
        {
          input: "1.00 КБ  ",
          expected: 1024,
          desc: "multiple trailing spaces",
        },
      ])("should handle $desc: '$input' → $expected", ({ input, expected }) => {
        expect(parseFileSize(input)).toBe(expected);
      });
    });

    /**
     * Failure scenarios - invalid inputs that should return 0
     */
    describe("failure scenarios", () => {
      /**
       * @description Handles invalid input
       * @scenario Input doesn't match expected format
       * @expected Returns 0
       */
      it.each([
        { input: "" },
        { input: "invalid" },
        { input: "1024" },
        { input: "Б" },
        { input: "1.00 ПБ" },
        { input: "abc КБ" },
      ])("should return 0 for invalid input: '$input'", ({ input }) => {
        expect(parseFileSize(input)).toBe(0);
      });

      /**
       * @description Does not handle negative sign in input
       * @scenario Input starts with minus sign
       * @expected Returns 0 (regex doesn't match negative values)
       */
      it.each([
        { input: "-1.00 КБ" },
        { input: "-500 Б" },
      ])("should return 0 for negative sign in string: '$input'", ({
        input,
      }) => {
        expect(parseFileSize(input)).toBe(0);
      });

      /**
       * @description Does not handle leading whitespace
       * @scenario Input has extra spaces at start
       * @expected Returns 0 (regex has ^ anchor)
       */
      it.each([
        { input: " 1.00 КБ", expected: 0, desc: "leading space" },
      ])("should return 0 for $desc: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });
    });

    /**
     * Edge cases - boundary values and precision tests
     */
    describe("edge cases", () => {
      /**
       * @description Handles very small decimal values
       * @scenario Input has small fractions
       * @expected Rounds to nearest integer byte
       */
      it.each([
        { input: "0.001 КБ", expected: 1 },
        { input: "0.0005 КБ", expected: 1 },
        { input: "0.0001 КБ", expected: 0 },
      ])("should round small decimal values: '$input' → $expected", ({
        input,
        expected,
      }) => {
        expect(parseFileSize(input)).toBe(expected);
      });

      /**
       * @description Handles large terabyte values
       * @scenario Very large terabyte values with decimals
       * @expected Returns correct byte value with rounding
       */
      it("should handle large terabyte values", () => {
        const expected = Math.round(999.99 * 1024 ** 4);
        expect(parseFileSize("999.99 ТБ")).toBe(expected);
      });
    });
  });

  // ---------------------------------------------------------------------------
  // INTEGRATION TESTS
  // ---------------------------------------------------------------------------

  /**
   * Integration tests - testing both functions together
   */
  describe("integration", () => {
    /**
     * Round-trip conversion tests
     */
    describe("round-trip conversion", () => {
      /**
       * @description Round-trip conversion
       * @scenario Format then parse the same value
       * @expected Returns approximately original value (within rounding)
       */
      it("should maintain consistency for single value", () => {
        const originalBytes = 1_572_864;
        const formatted = formatFileSize(originalBytes);
        const parsed = parseFileSize(formatted);
        expect(parsed).toBeCloseTo(originalBytes, 0);
      });

      /**
       * @description Round-trip with different units
       * @scenario Test multiple unit conversions
       * @expected All conversions maintain consistency within rounding
       */
      it.each([
        { bytes: 500 },
        { bytes: 1024 },
        { bytes: 1_048_576 },
        { bytes: 1_073_741_824 },
        { bytes: 1_099_511_627_776 },
      ])("should maintain consistency for $bytes bytes", ({ bytes }) => {
        const formatted = formatFileSize(bytes);
        const parsed = parseFileSize(formatted);
        expect(parsed).toBeCloseTo(bytes, 0);
      });
    });

    /**
     * Sign handling in round-trip
     */
    describe("sign handling", () => {
      /**
       * @description Parse formatted negative value
       * @scenario Format negative bytes and parse result
       * @expected parseFileSize returns 0 (doesn't handle sign)
       */
      it("should return 0 when parsing formatted negative value", () => {
        const negativeBytes = -1024;
        const formatted = formatFileSize(negativeBytes); // "-1.00 КБ"
        const parsed = parseFileSize(formatted); // 0 (regex doesn't match "-")
        expect(parsed).toBe(0);
      });
    });
  });
});
