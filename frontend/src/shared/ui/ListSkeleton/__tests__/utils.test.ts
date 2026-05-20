import { describe, expect, it } from "vitest";

import { generateSkeletonKeys } from "../utils";

describe("generateSkeletonKeys", () => {
  describe("when generating header keys", () => {
    /**
     * @description Should generate correct number of header keys based on columnCount
     * @scenario Call generateSkeletonKeys with columnCount = 5, rowCount = 3
     * @expected headerKeys array length equals columnCount (5)
     */
    it("should generate headerKeys array with length equal to columnCount", () => {
      // Arrange
      const columnCount = 5;
      const rowCount = 3;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.headerKeys).toHaveLength(columnCount);
    });

    /**
     * @description Should generate header keys in format "header-{index}"
     * @scenario Call generateSkeletonKeys with columnCount = 3
     * @expected headerKeys values are "header-0", "header-1", "header-2"
     */
    it('should generate header keys with pattern "header-{index}"', () => {
      // Arrange
      const columnCount = 3;
      const rowCount = 1;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.headerKeys).toEqual(["header-0", "header-1", "header-2"]);
    });
  });

  // ===========================================================================

  describe("when generating grid rows", () => {
    /**
     * @description Should generate correct number of rows based on rowCount
     * @scenario Call generateSkeletonKeys with columnCount = 4, rowCount = 6
     * @expected gridRows array length equals rowCount (6)
     */
    it("should generate gridRows array with length equal to rowCount", () => {
      // Arrange
      const columnCount = 4;
      const rowCount = 6;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.gridRows).toHaveLength(rowCount);
    });

    /**
     * @description Should generate rowKey in format "row-{rowIndex}"
     * @scenario Call generateSkeletonKeys with rowCount = 2
     * @expected rowKey values are "row-0", "row-1"
     */
    it('should generate rowKey with pattern "row-{rowIndex}"', () => {
      // Arrange
      const columnCount = 2;
      const rowCount = 2;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.gridRows[0].rowKey).toBe("row-0");
      expect(result.gridRows[1].rowKey).toBe("row-1");
    });

    /**
     * @description Should generate cellKeys array for each row with length equal to columnCount
     * @scenario Call generateSkeletonKeys with columnCount = 4, rowCount = 2
     * @expected Each row's cellKeys has length = columnCount (4)
     */
    it("should generate cellKeys array with length equal to columnCount for each row", () => {
      // Arrange
      const columnCount = 4;
      const rowCount = 2;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      result.gridRows.forEach((row) => {
        expect(row.cellKeys).toHaveLength(columnCount);
      });
    });

    /**
     * @description Should generate cell keys in format "row-{rowIndex}-col-{colIndex}"
     * @scenario Call generateSkeletonKeys with columnCount = 3, rowCount = 2
     * @expected cellKeys match expected pattern for each cell
     */
    it('should generate cell keys with pattern "row-{rowIndex}-col-{colIndex}"', () => {
      // Arrange
      const columnCount = 3;
      const rowCount = 2;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      const expectedCellKeys = [
        ["row-0-col-0", "row-0-col-1", "row-0-col-2"],
        ["row-1-col-0", "row-1-col-1", "row-1-col-2"],
      ];

      result.gridRows.forEach((row, rowIndex) => {
        expect(row.cellKeys).toEqual(expectedCellKeys[rowIndex]);
      });
    });
  });

  // ===========================================================================

  describe("edge cases", () => {
    /**
     * @description Should return empty headerKeys array when columnCount is 0
     * @scenario Call generateSkeletonKeys with columnCount = 0, rowCount = 3
     * @expected headerKeys is empty array, gridRows have cellKeys empty for each row
     */
    it("should return empty headerKeys when columnCount is 0", () => {
      // Arrange
      const columnCount = 0;
      const rowCount = 3;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.headerKeys).toEqual([]);
      expect(result.gridRows).toHaveLength(rowCount);
      result.gridRows.forEach((row) => {
        expect(row.cellKeys).toEqual([]);
      });
    });

    /**
     * @description Should return empty gridRows array when rowCount is 0
     * @scenario Call generateSkeletonKeys with columnCount = 5, rowCount = 0
     * @expected gridRows is empty array, headerKeys still generated
     */
    it("should return empty gridRows when rowCount is 0", () => {
      // Arrange
      const columnCount = 5;
      const rowCount = 0;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.gridRows).toEqual([]);
      expect(result.headerKeys).toHaveLength(columnCount);
    });

    /**
     * @description Should return both empty arrays when columnCount and rowCount are 0
     * @scenario Call generateSkeletonKeys with columnCount = 0, rowCount = 0
     * @expected headerKeys and gridRows are empty arrays
     */
    it("should return empty headerKeys and empty gridRows when both counts are zero", () => {
      // Arrange
      const columnCount = 0;
      const rowCount = 0;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.headerKeys).toEqual([]);
      expect(result.gridRows).toEqual([]);
    });

    /**
     * @description Should handle large numbers without performance issues or incorrect patterns
     * @scenario Call generateSkeletonKeys with columnCount = 100, rowCount = 50
     * @expected Header and row counts match, keys follow correct pattern
     */
    it("should handle large columnCount and rowCount correctly", () => {
      // Arrange
      const columnCount = 100;
      const rowCount = 50;

      // Act
      const result = generateSkeletonKeys(columnCount, rowCount);

      // Assert
      expect(result.headerKeys).toHaveLength(columnCount);
      expect(result.gridRows).toHaveLength(rowCount);
      expect(result.headerKeys[0]).toBe("header-0");
      expect(result.headerKeys[columnCount - 1]).toBe(
        `header-${columnCount - 1}`,
      );
      expect(result.gridRows[0].rowKey).toBe("row-0");
      expect(result.gridRows[rowCount - 1].rowKey).toBe(`row-${rowCount - 1}`);
      expect(result.gridRows[0].cellKeys).toHaveLength(columnCount);
      expect(result.gridRows[0].cellKeys[0]).toBe("row-0-col-0");
      expect(result.gridRows[0].cellKeys[columnCount - 1]).toBe(
        `row-0-col-${columnCount - 1}`,
      );
    });
  });
});
