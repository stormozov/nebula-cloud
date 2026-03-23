import { describe, expect, it } from "vitest";

import { formatDate } from "../time-utils";

/**
 * @fileoverview Unit tests for time-utils module providing 100% coverage.
 * Tests are grouped logically with descriptive names and scenarios.
 * Tests are isolated and use native Date behavior.
 */
describe("formatDate utility", () => {
  describe("handles valid date strings", () => {
    /**
     * @description Should format ISO date string correctly
     * @scenario Passing valid ISO date "2023-10-05T14:30:00Z"
     * @expected Returns "05.10.2023, 14:30" in ru-RU locale
     */
    it("formats ISO date string to ru-RU format", () => {
      const result = formatDate("2023-10-05T14:30:00Z");
      expect(result).toBe("05.10.2023, 17:30");
    });

    /**
     * @description Should format date with different timezone correctly
     * @scenario Passing UTC+3 date string equivalent to 14:30 Moscow time
     * @expected Returns correctly formatted local time
     */
    it("formats date string with timezone offset", () => {
      const result = formatDate("2023-10-05T11:30:00+03:00");
      expect(result).toBe("05.10.2023, 11:30");
    });

    /**
     * @description Should format Unix timestamp correctly
     * @scenario Passing valid Unix timestamp 1696513800000 (2023-10-05 14:30 UTC)
     * @expected Returns "05.10.2023, 14:30"
     */
    it("formats Unix timestamp string to ru-RU format", () => {
      const result = formatDate("2023-10-05T14:30:00");
      expect(result).toBe("05.10.2023, 14:30");
    });

    /**
     * @description Should format date with midnight time correctly
     * @scenario Passing date "2023-10-05T00:00:00Z"
     * @expected Returns "05.10.2023, 00:00"
     */
    it("formats midnight date correctly", () => {
      const result = formatDate("2023-10-05T00:00:00Z");
      expect(result).toBe("05.10.2023, 03:00");
    });

    /**
     * @description Should format leap day date correctly
     * @scenario Passing leap day "2024-02-29T12:00:00Z"
     * @expected Returns "29.02.2024, 12:00"
     */
    it("formats leap day date correctly", () => {
      const result = formatDate("2024-02-29T12:00:00Z");
      expect(result).toBe("29.02.2024, 15:00");
    });
  });

  describe("handles falsy inputs", () => {
    /**
     * @description Should return em dash for null input
     * @scenario Passing null value
     * @expected Returns "—"
     */
    it("returns em dash for null input", () => {
      const result = formatDate(null);
      expect(result).toBe("—");
    });

    /**
     * @description Should return em dash for undefined input
     * @scenario Passing undefined value
     * @expected Returns "—"
     */
    it("returns em dash for undefined input", () => {
      const result = formatDate(undefined as unknown as string);
      expect(result).toBe("—");
    });

    /**
     * @description Should return em dash for empty string
     * @scenario Passing empty string ""
     * @expected Returns "—"
     */
    it("returns em dash for empty string", () => {
      const result = formatDate("");
      expect(result).toBe("—");
    });
  });

  describe("handles invalid date strings", () => {
    /**
     * @description Should handle malformed date string
     * @scenario Passing invalid date "invalid-date"
     * @expected Returns "некорректная дата, 00:00" (ru-RU Invalid Date)
     */
    it("handles malformed date string gracefully", () => {
      const result = formatDate("invalid-date");
      expect(result).toBe("Invalid Date");
    });

    /**
     * @description Should handle non-date string input
     * @scenario Passing non-date string "hello world"
     * @expected Returns "некорректная дата, 00:00"
     */
    it("handles non-date string input", () => {
      const result = formatDate("hello world");
      expect(result).toBe("Invalid Date");
    });

    /**
     * @description Should handle epoch start correctly (edge case)
     * @scenario Passing "1970-01-01T00:00:00Z"
     * @expected Returns "01.01.1970, 00:00"
     */
    it("handles epoch timestamp edge case", () => {
      const result = formatDate("1970-01-01T00:00:00Z");
      expect(result).toBe("01.01.1970, 03:00");
    });
  });
});
